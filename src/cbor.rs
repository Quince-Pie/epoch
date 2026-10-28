//! Deterministic RFC 8949 §4.2.1 CBOR Encoder and Decoder (`plan.cbor`, `state.cbor`, `epoch-secrets.cbor`, QUIC wire frames).
//!
//! Data-Oriented Design (DoD) & Zero-Copy Architecture:
//! - **Direct Streaming Canonical Encoder (`DirectSerializer`)**: Serializes primitive values, byte
//!   slices, text strings, and known-length sequences directly into a single contiguous `Vec<u8>`
//!   output buffer without constructing an intermediate heap `CborValue` AST. Map and struct entries
//!   are staged into a contiguous scratch byte arena indexed by 12-byte POD `MapEntrySpan` descriptors
//!   (`key_start`, `key_end`, `val_end`), sorted in-place by RFC 8949 §4.2.1 bytewise lexicographic
//!   key order, and copied contiguously into the output stream.
//! - **Zero-AST Borrowed Slice Decoder (`SliceDeserializer<'de>`)**: Parses directly from `&'de [u8]`
//!   using a stack cursor (`&mut usize`), borrowing `&'de str` (for struct field identifiers, enum
//!   variants, and borrowed strings) and `&'de [u8]` directly from the input buffer with zero
//!   intermediate `CborValue` tree allocations.

use serde::de::{
    self, Deserialize, DeserializeOwned, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::ser::{
    self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant, Serializer,
};
use std::cell::RefCell;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CborError(pub String);

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CBOR error: {}", self.0)
    }
}

impl std::error::Error for CborError {}

impl ser::Error for CborError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        CborError(msg.to_string())
    }
}

impl de::Error for CborError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        CborError(msg.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CborError>;

/// Retained AST representation for explicit tree inspection and backwards compatibility.
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    Unsigned(u64),
    Negative(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Bool(bool),
    Null,
    Float(f64),
}

/// Serialize `value` into RFC 8949 deterministic CBOR bytes using the zero-AST streaming encoder.
pub fn to_vec_deterministic<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let _zone = crate::tracy_zone!("cbor::to_vec_deterministic", 0xf59e0b);
    let mut out = Vec::with_capacity(256);
    value.serialize(DirectSerializer { out: &mut out })?;
    _zone.value(out.len() as u64);
    Ok(out)
}

/// Serialize `value` directly into a caller-supplied `Vec<u8>` buffer (clearing or appending).
#[inline]
pub fn encode_into_deterministic<T: Serialize + ?Sized>(
    value: &T,
    out: &mut Vec<u8>,
) -> Result<()> {
    value.serialize(DirectSerializer { out })
}

/// Deserialize `T` from RFC 8949 CBOR bytes without allocating an intermediate `CborValue` AST.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    from_slice_borrowed(bytes)
}

pub const MAX_CBOR_DEPTH: u8 = 128;

/// Deserialize `T` from RFC 8949 CBOR bytes, allowing `T` to borrow `&'de str` and `&'de [u8]`
/// slices directly from `bytes` (`'de` lifetime).
pub fn from_slice_borrowed<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T> {
    let _zone = crate::tracy_zone!("cbor::from_slice", 0xf97316);
    _zone.value(bytes.len() as u64);
    let mut pos = 0;
    let val = T::deserialize(SliceDeserializer {
        bytes,
        pos: &mut pos,
        depth: 0,
    })?;
    if pos != bytes.len() {
        return Err(CborError(format!(
            "trailing bytes after root CBOR item: {} extra bytes",
            bytes.len() - pos
        )));
    }
    Ok(val)
}

#[inline(always)]
fn write_type_and_arg(major: u8, arg: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    if arg < 24 {
        out.push(prefix | (arg as u8));
    } else if arg <= u8::MAX as u64 {
        out.extend_from_slice(&[prefix | 24, arg as u8]);
    } else if arg <= u16::MAX as u64 {
        let be = (arg as u16).to_be_bytes();
        out.extend_from_slice(&[prefix | 25, be[0], be[1]]);
    } else if arg <= u32::MAX as u64 {
        let be = (arg as u32).to_be_bytes();
        out.extend_from_slice(&[prefix | 26, be[0], be[1], be[2], be[3]]);
    } else {
        let be = arg.to_be_bytes();
        out.push(prefix | 27);
        out.extend_from_slice(&be);
    }
}

#[inline(always)]
fn write_text_str(s: &str, out: &mut Vec<u8>) {
    let b = s.as_bytes();
    write_type_and_arg(3, b.len() as u64, out);
    out.extend_from_slice(b);
}

#[inline(always)]
fn write_byte_slice(b: &[u8], out: &mut Vec<u8>) {
    write_type_and_arg(2, b.len() as u64, out);
    out.extend_from_slice(b);
}

// ============================================================================
// Data-Oriented Direct Streaming Canonical Serializer (`DirectSerializer`)
// ============================================================================

/// 12-byte POD descriptor indexing a contiguous `(key, value)` byte span inside a scratch buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct MapEntrySpan {
    key_start: u32,
    key_end: u32,
    val_end: u32,
}

struct ScratchArenaPool {
    byte_bufs: Vec<Vec<u8>>,
    span_bufs: Vec<Vec<MapEntrySpan>>,
}

thread_local! {
    static SCRATCH_POOL: RefCell<ScratchArenaPool> = RefCell::new(ScratchArenaPool {
        byte_bufs: Vec::with_capacity(4),
        span_bufs: Vec::with_capacity(4),
    });
}

#[inline]
fn acquire_scratch(cap_entries: usize) -> (Vec<u8>, Vec<MapEntrySpan>) {
    SCRATCH_POOL.with(|pool| {
        let mut p = pool.borrow_mut();
        let mut bytes = p
            .byte_bufs
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(cap_entries.saturating_mul(32).max(128)));
        bytes.clear();
        let mut spans = p
            .span_bufs
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(cap_entries.max(8)));
        spans.clear();
        (bytes, spans)
    })
}

#[inline]
fn release_scratch(mut bytes: Vec<u8>, mut spans: Vec<MapEntrySpan>) {
    if bytes.capacity() <= 64 * 1024 && spans.capacity() <= 1024 {
        bytes.clear();
        spans.clear();
        SCRATCH_POOL.with(|pool| {
            let mut p = pool.borrow_mut();
            if p.byte_bufs.len() < 4 {
                p.byte_bufs.push(bytes);
                p.span_bufs.push(spans);
            }
        });
    }
}

#[inline]
fn flush_canonical_map_spans(scratch: Vec<u8>, mut spans: Vec<MapEntrySpan>, out: &mut Vec<u8>) {
    write_type_and_arg(5, spans.len() as u64, out);
    // RFC 8949 §4.2.1: Sort map keys by bytewise lexicographic order of their deterministic encoding.
    if spans.len() > 1 {
        spans.sort_unstable_by(|a, b| {
            let ka = &scratch[a.key_start as usize..a.key_end as usize];
            let kb = &scratch[b.key_start as usize..b.key_end as usize];
            ka.cmp(kb)
        });
    }
    out.reserve(scratch.len());
    for sp in &spans {
        out.extend_from_slice(&scratch[sp.key_start as usize..sp.val_end as usize]);
    }
    release_scratch(scratch, spans);
}

struct DirectSerializer<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Serializer for DirectSerializer<'a> {
    type Ok = ();
    type Error = CborError;
    type SerializeSeq = DirectSeqCollector<'a>;
    type SerializeTuple = DirectKnownSeqCollector<'a>;
    type SerializeTupleStruct = DirectKnownSeqCollector<'a>;
    type SerializeTupleVariant = DirectTupleVariantCollector<'a>;
    type SerializeMap = DirectMapCollector<'a>;
    type SerializeStruct = DirectStructCollector<'a>;
    type SerializeStructVariant = DirectStructVariantCollector<'a>;

    #[inline(always)]
    fn serialize_bool(self, v: bool) -> Result<()> {
        self.out.push(if v { 0xf5 } else { 0xf4 });
        Ok(())
    }

    #[inline(always)]
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    #[inline(always)]
    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    #[inline(always)]
    fn serialize_i32(self, v: i32) -> Result<()> {
        self.serialize_i64(v as i64)
    }

    #[inline(always)]
    fn serialize_i64(self, v: i64) -> Result<()> {
        if v >= 0 {
            write_type_and_arg(0, v as u64, self.out);
        } else {
            let arg = (-1i128 - (v as i128)) as u64;
            write_type_and_arg(1, arg, self.out);
        }
        Ok(())
    }

    #[inline(always)]
    fn serialize_i128(self, v: i128) -> Result<()> {
        if v >= 0 {
            let arg = u64::try_from(v)
                .map_err(|_| CborError("i128 value exceeds CBOR unsigned 64-bit range".into()))?;
            write_type_and_arg(0, arg, self.out);
            Ok(())
        } else {
            let arg = u64::try_from(-1i128 - v)
                .map_err(|_| CborError("i128 value exceeds CBOR negative 64-bit range".into()))?;
            write_type_and_arg(1, arg, self.out);
            Ok(())
        }
    }

    #[inline(always)]
    fn serialize_u8(self, v: u8) -> Result<()> {
        write_type_and_arg(0, v as u64, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_u16(self, v: u16) -> Result<()> {
        write_type_and_arg(0, v as u64, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_u32(self, v: u32) -> Result<()> {
        write_type_and_arg(0, v as u64, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_u64(self, v: u64) -> Result<()> {
        write_type_and_arg(0, v, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_u128(self, v: u128) -> Result<()> {
        let arg = u64::try_from(v)
            .map_err(|_| CborError("u128 value exceeds CBOR unsigned 64-bit range".into()))?;
        write_type_and_arg(0, arg, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_f32(self, v: f32) -> Result<()> {
        self.serialize_f64(v as f64)
    }

    #[inline(always)]
    fn serialize_f64(self, v: f64) -> Result<()> {
        self.out.push(0xfb);
        self.out.extend_from_slice(&v.to_bits().to_be_bytes());
        Ok(())
    }

    #[inline(always)]
    fn serialize_char(self, v: char) -> Result<()> {
        let mut buf = [0u8; 4];
        let s = v.encode_utf8(&mut buf);
        write_text_str(s, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_str(self, v: &str) -> Result<()> {
        write_text_str(v, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        write_byte_slice(v, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_none(self) -> Result<()> {
        self.out.push(0xf6);
        Ok(())
    }

    #[inline(always)]
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<()> {
        value.serialize(self)
    }

    #[inline(always)]
    fn serialize_unit(self) -> Result<()> {
        self.out.push(0xf6);
        Ok(())
    }

    #[inline(always)]
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        self.out.push(0xf6);
        Ok(())
    }

    #[inline(always)]
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<()> {
        write_text_str(variant, self.out);
        Ok(())
    }

    #[inline(always)]
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<()> {
        value.serialize(self)
    }

    #[inline]
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<()> {
        write_type_and_arg(5, 1, self.out);
        write_text_str(variant, self.out);
        value.serialize(self)
    }

    #[inline]
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        if let Some(n) = len {
            write_type_and_arg(4, n as u64, self.out);
            Ok(DirectSeqCollector::KnownLen { out: self.out })
        } else {
            Ok(DirectSeqCollector::UnknownLen {
                out: self.out,
                scratch: Vec::with_capacity(64),
                count: 0,
            })
        }
    }

    #[inline(always)]
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
        write_type_and_arg(4, len as u64, self.out);
        Ok(DirectKnownSeqCollector { out: self.out })
    }

    #[inline(always)]
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        write_type_and_arg(4, len as u64, self.out);
        Ok(DirectKnownSeqCollector { out: self.out })
    }

    #[inline]
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        write_type_and_arg(5, 1, self.out);
        write_text_str(variant, self.out);
        write_type_and_arg(4, len as u64, self.out);
        Ok(DirectTupleVariantCollector { out: self.out })
    }

    #[inline]
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap> {
        let (scratch, spans) = acquire_scratch(len.unwrap_or(8));
        Ok(DirectMapCollector {
            out: self.out,
            scratch,
            spans,
            cur_key_start: 0,
            cur_key_end: 0,
        })
    }

    #[inline]
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
        let (scratch, spans) = acquire_scratch(len);
        Ok(DirectStructCollector {
            out: self.out,
            scratch,
            spans,
        })
    }

    #[inline]
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        write_type_and_arg(5, 1, self.out);
        write_text_str(variant, self.out);
        let (scratch, spans) = acquire_scratch(len);
        Ok(DirectStructVariantCollector {
            out: self.out,
            scratch,
            spans,
        })
    }
}

enum DirectSeqCollector<'a> {
    KnownLen {
        out: &'a mut Vec<u8>,
    },
    UnknownLen {
        out: &'a mut Vec<u8>,
        scratch: Vec<u8>,
        count: u64,
    },
}

impl<'a> SerializeSeq for DirectSeqCollector<'a> {
    type Ok = ();
    type Error = CborError;

    #[inline(always)]
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        match self {
            DirectSeqCollector::KnownLen { out } => value.serialize(DirectSerializer { out }),
            DirectSeqCollector::UnknownLen { scratch, count, .. } => {
                *count += 1;
                value.serialize(DirectSerializer { out: scratch })
            }
        }
    }

    #[inline(always)]
    fn end(self) -> Result<()> {
        if let DirectSeqCollector::UnknownLen {
            out,
            scratch,
            count,
        } = self
        {
            write_type_and_arg(4, count, out);
            out.extend_from_slice(&scratch);
        }
        Ok(())
    }
}

struct DirectKnownSeqCollector<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> SerializeTuple for DirectKnownSeqCollector<'a> {
    type Ok = ();
    type Error = CborError;

    #[inline(always)]
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(DirectSerializer { out: self.out })
    }

    #[inline(always)]
    fn end(self) -> Result<()> {
        Ok(())
    }
}

impl<'a> SerializeTupleStruct for DirectKnownSeqCollector<'a> {
    type Ok = ();
    type Error = CborError;

    #[inline(always)]
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(DirectSerializer { out: self.out })
    }

    #[inline(always)]
    fn end(self) -> Result<()> {
        Ok(())
    }
}

struct DirectTupleVariantCollector<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> SerializeTupleVariant for DirectTupleVariantCollector<'a> {
    type Ok = ();
    type Error = CborError;

    #[inline(always)]
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(DirectSerializer { out: self.out })
    }

    #[inline(always)]
    fn end(self) -> Result<()> {
        Ok(())
    }
}

struct DirectMapCollector<'a> {
    out: &'a mut Vec<u8>,
    scratch: Vec<u8>,
    spans: Vec<MapEntrySpan>,
    cur_key_start: u32,
    cur_key_end: u32,
}

impl<'a> SerializeMap for DirectMapCollector<'a> {
    type Ok = ();
    type Error = CborError;

    #[inline]
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<()> {
        self.cur_key_start = self.scratch.len() as u32;
        key.serialize(DirectSerializer {
            out: &mut self.scratch,
        })?;
        self.cur_key_end = self.scratch.len() as u32;
        Ok(())
    }

    #[inline]
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
        value.serialize(DirectSerializer {
            out: &mut self.scratch,
        })?;
        let val_end = self.scratch.len() as u32;
        self.spans.push(MapEntrySpan {
            key_start: self.cur_key_start,
            key_end: self.cur_key_end,
            val_end,
        });
        Ok(())
    }

    #[inline]
    fn end(self) -> Result<()> {
        flush_canonical_map_spans(self.scratch, self.spans, self.out);
        Ok(())
    }
}

struct DirectStructCollector<'a> {
    out: &'a mut Vec<u8>,
    scratch: Vec<u8>,
    spans: Vec<MapEntrySpan>,
}

impl<'a> SerializeStruct for DirectStructCollector<'a> {
    type Ok = ();
    type Error = CborError;

    #[inline]
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        let key_start = self.scratch.len() as u32;
        write_text_str(key, &mut self.scratch);
        let key_end = self.scratch.len() as u32;
        value.serialize(DirectSerializer {
            out: &mut self.scratch,
        })?;
        let val_end = self.scratch.len() as u32;
        self.spans.push(MapEntrySpan {
            key_start,
            key_end,
            val_end,
        });
        Ok(())
    }

    #[inline]
    fn end(self) -> Result<()> {
        flush_canonical_map_spans(self.scratch, self.spans, self.out);
        Ok(())
    }
}

struct DirectStructVariantCollector<'a> {
    out: &'a mut Vec<u8>,
    scratch: Vec<u8>,
    spans: Vec<MapEntrySpan>,
}

impl<'a> SerializeStructVariant for DirectStructVariantCollector<'a> {
    type Ok = ();
    type Error = CborError;

    #[inline]
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        let key_start = self.scratch.len() as u32;
        write_text_str(key, &mut self.scratch);
        let key_end = self.scratch.len() as u32;
        value.serialize(DirectSerializer {
            out: &mut self.scratch,
        })?;
        let val_end = self.scratch.len() as u32;
        self.spans.push(MapEntrySpan {
            key_start,
            key_end,
            val_end,
        });
        Ok(())
    }

    #[inline]
    fn end(self) -> Result<()> {
        flush_canonical_map_spans(self.scratch, self.spans, self.out);
        Ok(())
    }
}

// ============================================================================
// Zero-AST Borrowed Slice Deserializer (`SliceDeserializer<'a, 'de>`)
// ============================================================================

#[inline(always)]
fn read_arg(bytes: &[u8], pos: &mut usize, info: u8) -> Result<u64> {
    if info < 24 {
        Ok(info as u64)
    } else if info == 24 {
        if *pos + 1 > bytes.len() {
            return Err(CborError("unexpected EOF reading u8 arg".into()));
        }
        let v = bytes[*pos] as u64;
        *pos += 1;
        Ok(v)
    } else if info == 25 {
        if *pos + 2 > bytes.len() {
            return Err(CborError("unexpected EOF reading u16 arg".into()));
        }
        let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]) as u64;
        *pos += 2;
        Ok(v)
    } else if info == 26 {
        if *pos + 4 > bytes.len() {
            return Err(CborError("unexpected EOF reading u32 arg".into()));
        }
        let v = u32::from_be_bytes([
            bytes[*pos],
            bytes[*pos + 1],
            bytes[*pos + 2],
            bytes[*pos + 3],
        ]) as u64;
        *pos += 4;
        Ok(v)
    } else if info == 27 {
        if *pos + 8 > bytes.len() {
            return Err(CborError("unexpected EOF reading u64 arg".into()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[*pos..*pos + 8]);
        *pos += 8;
        Ok(u64::from_be_bytes(arr))
    } else {
        Err(CborError(format!(
            "unsupported or indefinite CBOR additional info: {info}"
        )))
    }
}

#[inline(always)]
fn read_borrowed_bytes<'de>(bytes: &'de [u8], pos: &mut usize, info: u8) -> Result<&'de [u8]> {
    let raw_len = read_arg(bytes, pos, info)?;
    let len = usize::try_from(raw_len)
        .map_err(|_| CborError("CBOR byte string length overflows usize".into()))?;
    if len > bytes.len().saturating_sub(*pos) {
        return Err(CborError("unexpected EOF in byte string".into()));
    }
    let slice = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

#[inline(always)]
fn read_borrowed_str<'de>(bytes: &'de [u8], pos: &mut usize, info: u8) -> Result<&'de str> {
    let raw_len = read_arg(bytes, pos, info)?;
    let len = usize::try_from(raw_len)
        .map_err(|_| CborError("CBOR text string length overflows usize".into()))?;
    if len > bytes.len().saturating_sub(*pos) {
        return Err(CborError("unexpected EOF in text string".into()));
    }
    let s = std::str::from_utf8(&bytes[*pos..*pos + len])
        .map_err(|e| CborError(format!("invalid UTF-8 in CBOR text string: {e}")))?;
    *pos += len;
    Ok(s)
}

struct SliceDeserializer<'a, 'de> {
    bytes: &'de [u8],
    pos: &'a mut usize,
    depth: u8,
}

impl<'a, 'de> de::Deserializer<'de> for SliceDeserializer<'a, 'de> {
    type Error = CborError;

    #[inline]
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if *self.pos >= self.bytes.len() {
            return Err(CborError("unexpected EOF decoding CBOR value".into()));
        }
        let initial = self.bytes[*self.pos];
        *self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;

        match major {
            0 => {
                let n = read_arg(self.bytes, self.pos, info)?;
                visitor.visit_u64(n)
            }
            1 => {
                let arg = read_arg(self.bytes, self.pos, info)?;
                let val = -1i128 - (arg as i128);
                if let Ok(v64) = i64::try_from(val) {
                    visitor.visit_i64(v64)
                } else {
                    visitor.visit_i128(val)
                }
            }
            2 => {
                let slice = read_borrowed_bytes(self.bytes, self.pos, info)?;
                visitor.visit_borrowed_bytes(slice)
            }
            3 => {
                let s = read_borrowed_str(self.bytes, self.pos, info)?;
                visitor.visit_borrowed_str(s)
            }
            4 => {
                if self.depth >= MAX_CBOR_DEPTH {
                    return Err(CborError(format!(
                        "CBOR nesting depth exceeded maximum ({MAX_CBOR_DEPTH})"
                    )));
                }
                let raw_len = read_arg(self.bytes, self.pos, info)?;
                let len = usize::try_from(raw_len)
                    .map_err(|_| CborError("CBOR array length overflows usize".into()))?;
                if len > self.bytes.len().saturating_sub(*self.pos) {
                    return Err(CborError(
                        "CBOR array length exceeds remaining input".into(),
                    ));
                }
                let mut seq = SliceSeqAccess {
                    bytes: self.bytes,
                    pos: self.pos,
                    remaining: len,
                    depth: self.depth + 1,
                };
                let val = visitor.visit_seq(&mut seq)?;
                if seq.remaining != 0 {
                    return Err(CborError(format!(
                        "unconsumed CBOR array elements: {} remaining",
                        seq.remaining
                    )));
                }
                Ok(val)
            }
            5 => {
                if self.depth >= MAX_CBOR_DEPTH {
                    return Err(CborError(format!(
                        "CBOR nesting depth exceeded maximum ({MAX_CBOR_DEPTH})"
                    )));
                }
                let raw_len = read_arg(self.bytes, self.pos, info)?;
                let len = usize::try_from(raw_len)
                    .map_err(|_| CborError("CBOR map length overflows usize".into()))?;
                if len > self.bytes.len().saturating_sub(*self.pos) / 2 {
                    return Err(CborError("CBOR map length exceeds remaining input".into()));
                }
                let mut map = SliceMapAccess {
                    bytes: self.bytes,
                    pos: self.pos,
                    remaining: len,
                    depth: self.depth + 1,
                };
                let val = visitor.visit_map(&mut map)?;
                if map.remaining != 0 {
                    return Err(CborError(format!(
                        "unconsumed CBOR map entries: {} remaining",
                        map.remaining
                    )));
                }
                Ok(val)
            }
            7 => match info {
                20 => visitor.visit_bool(false),
                21 => visitor.visit_bool(true),
                22 | 23 => visitor.visit_unit(),
                26 => {
                    if *self.pos + 4 > self.bytes.len() {
                        return Err(CborError("unexpected EOF reading f32".into()));
                    }
                    let bits = u32::from_be_bytes([
                        self.bytes[*self.pos],
                        self.bytes[*self.pos + 1],
                        self.bytes[*self.pos + 2],
                        self.bytes[*self.pos + 3],
                    ]);
                    *self.pos += 4;
                    visitor.visit_f64(f32::from_bits(bits) as f64)
                }
                27 => {
                    if *self.pos + 8 > self.bytes.len() {
                        return Err(CborError("unexpected EOF reading f64".into()));
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&self.bytes[*self.pos..*self.pos + 8]);
                    *self.pos += 8;
                    visitor.visit_f64(f64::from_bits(u64::from_be_bytes(arr)))
                }
                other => Err(CborError(format!(
                    "unsupported CBOR simple/float info: {other}"
                ))),
            },
            other => Err(CborError(format!("unsupported CBOR major type: {other}"))),
        }
    }

    #[inline(always)]
    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_any(visitor)
    }

    #[inline(always)]
    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_any(visitor)
    }

    #[inline]
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if *self.pos >= self.bytes.len() {
            return Err(CborError("unexpected EOF decoding CBOR option".into()));
        }
        let initial = self.bytes[*self.pos];
        if initial == 0xf6 || initial == 0xf7 {
            *self.pos += 1;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    #[inline(always)]
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    #[inline]
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if *self.pos >= self.bytes.len() {
            return Err(CborError("unexpected EOF decoding CBOR seq".into()));
        }
        let initial = self.bytes[*self.pos];
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            4 => {
                if self.depth >= MAX_CBOR_DEPTH {
                    return Err(CborError(format!(
                        "CBOR nesting depth exceeded maximum ({MAX_CBOR_DEPTH})"
                    )));
                }
                *self.pos += 1;
                let raw_len = read_arg(self.bytes, self.pos, info)?;
                let len = usize::try_from(raw_len)
                    .map_err(|_| CborError("CBOR array length overflows usize".into()))?;
                if len > self.bytes.len().saturating_sub(*self.pos) {
                    return Err(CborError(
                        "CBOR array length exceeds remaining input".into(),
                    ));
                }
                let mut seq = SliceSeqAccess {
                    bytes: self.bytes,
                    pos: self.pos,
                    remaining: len,
                    depth: self.depth + 1,
                };
                let val = visitor.visit_seq(&mut seq)?;
                if seq.remaining != 0 {
                    return Err(CborError(format!(
                        "unconsumed CBOR array elements: {} remaining",
                        seq.remaining
                    )));
                }
                Ok(val)
            }
            2 => {
                *self.pos += 1;
                let slice = read_borrowed_bytes(self.bytes, self.pos, info)?;
                let mut seq = ByteSliceSeqAccess { slice };
                let val = visitor.visit_seq(&mut seq)?;
                if !seq.slice.is_empty() {
                    return Err(CborError(format!(
                        "unconsumed bytes in CBOR byte string sequence: {} remaining",
                        seq.slice.len()
                    )));
                }
                Ok(val)
            }
            other => Err(CborError(format!(
                "expected CBOR array or bytes for seq, got major type {other}"
            ))),
        }
    }

    #[inline(always)]
    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }

    #[inline(always)]
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }

    #[inline]
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if *self.pos >= self.bytes.len() {
            return Err(CborError("unexpected EOF decoding CBOR bytes".into()));
        }
        let initial = self.bytes[*self.pos];
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            2 => {
                *self.pos += 1;
                let slice = read_borrowed_bytes(self.bytes, self.pos, info)?;
                visitor.visit_borrowed_bytes(slice)
            }
            4 => {
                if self.depth >= MAX_CBOR_DEPTH {
                    return Err(CborError(format!(
                        "CBOR nesting depth exceeded maximum ({MAX_CBOR_DEPTH})"
                    )));
                }
                *self.pos += 1;
                let raw_len = read_arg(self.bytes, self.pos, info)?;
                let len = usize::try_from(raw_len)
                    .map_err(|_| CborError("CBOR byte array length overflows usize".into()))?;
                if len > self.bytes.len().saturating_sub(*self.pos) {
                    return Err(CborError(
                        "CBOR byte array length exceeds remaining input".into(),
                    ));
                }
                let mut buf = Vec::with_capacity(len.min(65536));
                for _ in 0..len {
                    if *self.pos >= self.bytes.len() {
                        return Err(CborError("unexpected EOF in CBOR byte array".into()));
                    }
                    let b_init = self.bytes[*self.pos];
                    *self.pos += 1;
                    if (b_init >> 5) != 0 {
                        return Err(CborError("expected unsigned byte in CBOR array".into()));
                    }
                    let n = read_arg(self.bytes, self.pos, b_init & 0x1f)?;
                    if n > u8::MAX as u64 {
                        return Err(CborError(format!("byte value out of u8 range: {n}")));
                    }
                    buf.push(n as u8);
                }
                visitor.visit_byte_buf(buf)
            }
            other => Err(CborError(format!(
                "expected CBOR bytes or array, got major type {other}"
            ))),
        }
    }

    #[inline(always)]
    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_bytes(visitor)
    }

    #[inline]
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        if *self.pos >= self.bytes.len() {
            return Err(CborError("unexpected EOF decoding CBOR enum".into()));
        }
        let initial = self.bytes[*self.pos];
        let major = initial >> 5;
        let info = initial & 0x1f;
        match major {
            3 => {
                *self.pos += 1;
                let variant = read_borrowed_str(self.bytes, self.pos, info)?;
                visitor.visit_enum(SliceEnumAccess {
                    variant,
                    bytes: self.bytes,
                    pos: self.pos,
                    has_value: false,
                    depth: self.depth,
                })
            }
            5 => {
                if self.depth >= MAX_CBOR_DEPTH {
                    return Err(CborError(format!(
                        "CBOR nesting depth exceeded maximum ({MAX_CBOR_DEPTH})"
                    )));
                }
                *self.pos += 1;
                let map_len = read_arg(self.bytes, self.pos, info)?;
                if map_len != 1 {
                    return Err(CborError(format!(
                        "expected single-entry map for enum, got length {map_len}"
                    )));
                }
                if *self.pos >= self.bytes.len() {
                    return Err(CborError("unexpected EOF reading enum variant key".into()));
                }
                let k_init = self.bytes[*self.pos];
                if (k_init >> 5) != 3 {
                    return Err(CborError(
                        "expected CBOR text string for enum variant key".into(),
                    ));
                }
                *self.pos += 1;
                let variant = read_borrowed_str(self.bytes, self.pos, k_init & 0x1f)?;
                visitor.visit_enum(SliceEnumAccess {
                    variant,
                    bytes: self.bytes,
                    pos: self.pos,
                    has_value: true,
                    depth: self.depth + 1,
                })
            }
            other => Err(CborError(format!(
                "expected text or single-entry map for enum, got major type {other}"
            ))),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string
        unit unit_struct map struct identifier ignored_any
    }
}

struct SliceSeqAccess<'a, 'de> {
    bytes: &'de [u8],
    pos: &'a mut usize,
    remaining: usize,
    depth: u8,
}

impl<'a, 'de> SeqAccess<'de> for &mut SliceSeqAccess<'a, 'de> {
    type Error = CborError;

    #[inline]
    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(SliceDeserializer {
            bytes: self.bytes,
            pos: self.pos,
            depth: self.depth,
        })
        .map(Some)
    }

    #[inline(always)]
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct ByteSliceSeqAccess<'de> {
    slice: &'de [u8],
}

impl<'de> SeqAccess<'de> for &mut ByteSliceSeqAccess<'de> {
    type Error = CborError;

    #[inline(always)]
    fn next_element_seed<T: de::DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>> {
        if let Some((&first, rest)) = self.slice.split_first() {
            self.slice = rest;
            let de: de::value::U8Deserializer<CborError> = first.into_deserializer();
            seed.deserialize(de).map(Some)
        } else {
            Ok(None)
        }
    }

    #[inline(always)]
    fn size_hint(&self) -> Option<usize> {
        Some(self.slice.len())
    }
}

struct SliceMapAccess<'a, 'de> {
    bytes: &'de [u8],
    pos: &'a mut usize,
    remaining: usize,
    depth: u8,
}

impl<'a, 'de> MapAccess<'de> for &mut SliceMapAccess<'a, 'de> {
    type Error = CborError;

    #[inline]
    fn next_key_seed<K: de::DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(SliceDeserializer {
            bytes: self.bytes,
            pos: self.pos,
            depth: self.depth,
        })
        .map(Some)
    }

    #[inline]
    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        seed.deserialize(SliceDeserializer {
            bytes: self.bytes,
            pos: self.pos,
            depth: self.depth,
        })
    }

    #[inline(always)]
    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

struct SliceEnumAccess<'a, 'de> {
    variant: &'de str,
    bytes: &'de [u8],
    pos: &'a mut usize,
    has_value: bool,
    depth: u8,
}

impl<'a, 'de> EnumAccess<'de> for SliceEnumAccess<'a, 'de> {
    type Error = CborError;
    type Variant = SliceVariantAccess<'a, 'de>;

    #[inline]
    fn variant_seed<V: de::DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant)> {
        let variant_de: de::value::BorrowedStrDeserializer<'de, CborError> =
            de::value::BorrowedStrDeserializer::new(self.variant);
        let val = seed.deserialize(variant_de)?;
        Ok((
            val,
            SliceVariantAccess {
                bytes: self.bytes,
                pos: self.pos,
                has_value: self.has_value,
                depth: self.depth,
            },
        ))
    }
}

struct SliceVariantAccess<'a, 'de> {
    bytes: &'de [u8],
    pos: &'a mut usize,
    has_value: bool,
    depth: u8,
}

impl<'a, 'de> VariantAccess<'de> for SliceVariantAccess<'a, 'de> {
    type Error = CborError;

    #[inline]
    fn unit_variant(self) -> Result<()> {
        if !self.has_value {
            return Ok(());
        }
        if *self.pos < self.bytes.len()
            && (self.bytes[*self.pos] == 0xf6 || self.bytes[*self.pos] == 0xf7)
        {
            *self.pos += 1;
            Ok(())
        } else {
            Err(CborError("expected unit variant without payload".into()))
        }
    }

    #[inline]
    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value> {
        if !self.has_value {
            return Err(CborError(
                "expected newtype variant payload, got unit variant".into(),
            ));
        }
        seed.deserialize(SliceDeserializer {
            bytes: self.bytes,
            pos: self.pos,
            depth: self.depth,
        })
    }

    #[inline]
    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        if !self.has_value {
            return Err(CborError(
                "expected tuple variant payload, got unit variant".into(),
            ));
        }
        de::Deserializer::deserialize_seq(
            SliceDeserializer {
                bytes: self.bytes,
                pos: self.pos,
                depth: self.depth,
            },
            visitor,
        )
    }

    #[inline]
    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        if !self.has_value {
            return Err(CborError(
                "expected struct variant payload, got unit variant".into(),
            ));
        }
        de::Deserializer::deserialize_any(
            SliceDeserializer {
                bytes: self.bytes,
                pos: self.pos,
                depth: self.depth,
            },
            visitor,
        )
    }
}

// ============================================================================
// Retained `CborValue` AST Encoder & Decoder (Public API Compatibility)
// ============================================================================

pub fn encode_canonical(val: &CborValue, out: &mut Vec<u8>) {
    match val {
        CborValue::Unsigned(n) => write_type_and_arg(0, *n, out),
        CborValue::Negative(n) => {
            let arg = (-1i128 - *n) as u64;
            write_type_and_arg(1, arg, out);
        }
        CborValue::Bytes(b) => write_byte_slice(b, out),
        CborValue::Text(s) => write_text_str(s, out),
        CborValue::Array(items) => {
            write_type_and_arg(4, items.len() as u64, out);
            for item in items {
                encode_canonical(item, out);
            }
        }
        CborValue::Map(entries) => {
            let (mut scratch, mut spans) = acquire_scratch(entries.len());
            for (k, v) in entries {
                let key_start = scratch.len() as u32;
                encode_canonical(k, &mut scratch);
                let key_end = scratch.len() as u32;
                encode_canonical(v, &mut scratch);
                let val_end = scratch.len() as u32;
                spans.push(MapEntrySpan {
                    key_start,
                    key_end,
                    val_end,
                });
            }
            flush_canonical_map_spans(scratch, spans, out);
        }
        CborValue::Bool(false) => out.push(0xf4),
        CborValue::Bool(true) => out.push(0xf5),
        CborValue::Null => out.push(0xf6),
        CborValue::Float(f) => {
            out.push(0xfb);
            out.extend_from_slice(&f.to_bits().to_be_bytes());
        }
    }
}

pub fn decode_value(bytes: &[u8], pos: &mut usize) -> Result<CborValue> {
    decode_value_depth(bytes, pos, 0)
}

fn decode_value_depth(bytes: &[u8], pos: &mut usize, depth: u8) -> Result<CborValue> {
    if *pos >= bytes.len() {
        return Err(CborError("unexpected EOF decoding CBOR value".into()));
    }
    let initial = bytes[*pos];
    *pos += 1;
    let major = initial >> 5;
    let info = initial & 0x1f;

    match major {
        0 => Ok(CborValue::Unsigned(read_arg(bytes, pos, info)?)),
        1 => {
            let arg = read_arg(bytes, pos, info)?;
            Ok(CborValue::Negative(-1i128 - (arg as i128)))
        }
        2 => Ok(CborValue::Bytes(
            read_borrowed_bytes(bytes, pos, info)?.to_vec(),
        )),
        3 => Ok(CborValue::Text(
            read_borrowed_str(bytes, pos, info)?.to_owned(),
        )),
        4 => {
            if depth >= MAX_CBOR_DEPTH {
                return Err(CborError(format!(
                    "CBOR nesting depth exceeded maximum ({MAX_CBOR_DEPTH})"
                )));
            }
            let raw_len = read_arg(bytes, pos, info)?;
            let len = usize::try_from(raw_len)
                .map_err(|_| CborError("CBOR array length overflows usize".into()))?;
            if len > bytes.len().saturating_sub(*pos) {
                return Err(CborError(
                    "CBOR array length exceeds remaining input".into(),
                ));
            }
            let mut items = Vec::with_capacity(len.min(4096));
            for _ in 0..len {
                items.push(decode_value_depth(bytes, pos, depth + 1)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => {
            if depth >= MAX_CBOR_DEPTH {
                return Err(CborError(format!(
                    "CBOR nesting depth exceeded maximum ({MAX_CBOR_DEPTH})"
                )));
            }
            let raw_len = read_arg(bytes, pos, info)?;
            let len = usize::try_from(raw_len)
                .map_err(|_| CborError("CBOR map length overflows usize".into()))?;
            if len > bytes.len().saturating_sub(*pos) / 2 {
                return Err(CborError("CBOR map length exceeds remaining input".into()));
            }
            let mut entries = Vec::with_capacity(len.min(4096));
            for _ in 0..len {
                let k = decode_value_depth(bytes, pos, depth + 1)?;
                let v = decode_value_depth(bytes, pos, depth + 1)?;
                entries.push((k, v));
            }
            Ok(CborValue::Map(entries))
        }
        7 => match info {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 | 23 => Ok(CborValue::Null),
            26 => {
                if *pos + 4 > bytes.len() {
                    return Err(CborError("unexpected EOF reading f32".into()));
                }
                let bits = u32::from_be_bytes([
                    bytes[*pos],
                    bytes[*pos + 1],
                    bytes[*pos + 2],
                    bytes[*pos + 3],
                ]);
                *pos += 4;
                Ok(CborValue::Float(f32::from_bits(bits) as f64))
            }
            27 => {
                if *pos + 8 > bytes.len() {
                    return Err(CborError("unexpected EOF reading f64".into()));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[*pos..*pos + 8]);
                *pos += 8;
                Ok(CborValue::Float(f64::from_bits(u64::from_be_bytes(arr))))
            }
            other => Err(CborError(format!(
                "unsupported CBOR simple/float info: {other}"
            ))),
        },
        other => Err(CborError(format!("unsupported CBOR major type: {other}"))),
    }
}

/// Zero-allocation serde helper for `[u8; 64]` Ed25519 signatures.
pub mod serde_sig64 {
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    #[inline(always)]
    pub fn serialize<S: Serializer>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(sig)
    }

    pub(crate) struct Sig64Visitor;

    impl<'de> Visitor<'de> for Sig64Visitor {
        type Value = [u8; 64];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a 64-byte Ed25519 signature")
        }

        #[inline]
        fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
            if v.len() != 64 {
                return Err(E::custom(format!(
                    "expected 64-byte Ed25519 signature, got {} bytes",
                    v.len()
                )));
            }
            let mut out = [0u8; 64];
            out.copy_from_slice(v);
            Ok(out)
        }

        #[inline]
        fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
            self.visit_bytes(v)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; 64];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::custom(
                    "expected 64-byte Ed25519 signature, got >64 elements",
                ));
            }
            Ok(out)
        }
    }

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        deserializer.deserialize_bytes(Sig64Visitor)
    }

    pub mod option {
        use super::Sig64Visitor;
        use serde::de::{Error as DeError, Visitor};
        use serde::{Deserializer, Serialize, Serializer};
        use std::fmt;

        struct SigBytesRef<'a>(&'a [u8; 64]);

        impl Serialize for SigBytesRef<'_> {
            #[inline]
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(self.0)
            }
        }

        #[inline]
        pub fn serialize<S: Serializer>(
            sig: &Option<[u8; 64]>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match sig {
                Some(s) => serializer.serialize_some(&SigBytesRef(s)),
                None => serializer.serialize_none(),
            }
        }

        struct OptSig64Visitor;

        impl<'de> Visitor<'de> for OptSig64Visitor {
            type Value = Option<[u8; 64]>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an optional 64-byte Ed25519 signature")
            }

            #[inline]
            fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            #[inline]
            fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            #[inline]
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_bytes(Sig64Visitor).map(Some)
            }
        }

        #[inline]
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<[u8; 64]>, D::Error> {
            deserializer.deserialize_option(OptSig64Visitor)
        }
    }
}

/// Zero-allocation serde helper for `[u8; 32]` hashes and keys (`Blake3Hash`, `Sha256Hash`, `Ed25519Pub`).
/// Serializes as a compact 34-byte CBOR Major Type 2 byte string (`0x58, 0x20, ...`) instead of a
/// 32-element integer sequence (~58–65 bytes). Deserializes from both Major Type 2 byte strings
/// and legacy Major Type 4 integer arrays.
pub mod serde_bytes32 {
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    #[inline(always)]
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub(crate) struct Bytes32Visitor;

    impl<'de> Visitor<'de> for Bytes32Visitor {
        type Value = [u8; 32];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a 32-byte array")
        }

        #[inline]
        fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
            if v.len() != 32 {
                return Err(E::custom(format!(
                    "expected 32-byte array, got {} bytes",
                    v.len()
                )));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(v);
            Ok(out)
        }

        #[inline]
        fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
            self.visit_bytes(v)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; 32];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::custom("expected 32-byte array, got >32 elements"));
            }
            Ok(out)
        }
    }

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        deserializer.deserialize_bytes(Bytes32Visitor)
    }

    pub mod option {
        use super::Bytes32Visitor;
        use serde::de::{Error as DeError, Visitor};
        use serde::{Deserializer, Serialize, Serializer};
        use std::fmt;

        struct Bytes32Ref<'a>(&'a [u8; 32]);

        impl Serialize for Bytes32Ref<'_> {
            #[inline(always)]
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(self.0)
            }
        }

        #[inline]
        pub fn serialize<S: Serializer>(
            val: &Option<[u8; 32]>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match val {
                Some(b) => serializer.serialize_some(&Bytes32Ref(b)),
                None => serializer.serialize_none(),
            }
        }

        struct OptBytes32Visitor;

        impl<'de> Visitor<'de> for OptBytes32Visitor {
            type Value = Option<[u8; 32]>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an optional 32-byte array")
            }

            #[inline]
            fn visit_none<E: DeError>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            #[inline]
            fn visit_unit<E: DeError>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            #[inline]
            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_bytes(Bytes32Visitor).map(Some)
            }
        }

        #[inline]
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<[u8; 32]>, D::Error> {
            deserializer.deserialize_option(OptBytes32Visitor)
        }
    }
}

/// Zero-allocation serde helper for `[u8; 12]` AEAD nonces.
pub mod serde_bytes12 {
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    #[inline(always)]
    pub fn serialize<S: Serializer>(bytes: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    struct Bytes12Visitor;

    impl<'de> Visitor<'de> for Bytes12Visitor {
        type Value = [u8; 12];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a 12-byte array")
        }

        #[inline]
        fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
            if v.len() != 12 {
                return Err(E::custom(format!(
                    "expected 12-byte array, got {} bytes",
                    v.len()
                )));
            }
            let mut out = [0u8; 12];
            out.copy_from_slice(v);
            Ok(out)
        }

        #[inline]
        fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
            self.visit_bytes(v)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; 12];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(A::Error::custom("expected 12-byte array, got >12 elements"));
            }
            Ok(out)
        }
    }

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 12], D::Error> {
        deserializer.deserialize_bytes(Bytes12Visitor)
    }
}

/// Zero-allocation serde helper for `Vec<[u8; 32]>` lists of 32-byte hashes.
pub mod serde_vec_bytes32 {
    use super::serde_bytes32::Bytes32Visitor;
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt;

    struct Bytes32Ref<'a>(&'a [u8; 32]);

    impl Serialize for Bytes32Ref<'_> {
        #[inline(always)]
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    struct Bytes32Elem([u8; 32]);

    impl<'de> Deserialize<'de> for Bytes32Elem {
        #[inline]
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer
                .deserialize_bytes(Bytes32Visitor)
                .map(Bytes32Elem)
        }
    }

    #[inline]
    pub fn serialize<S: Serializer>(hashes: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(hashes.len()))?;
        for h in hashes {
            seq.serialize_element(&Bytes32Ref(h))?;
        }
        seq.end()
    }

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<[u8; 32]>, D::Error> {
        struct VecBytes32Visitor;

        impl<'de> Visitor<'de> for VecBytes32Visitor {
            type Value = Vec<[u8; 32]>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a sequence of 32-byte hashes")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
                while let Some(Bytes32Elem(h)) = seq.next_element()? {
                    out.push(h);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_seq(VecBytes32Visitor)
    }
}

/// Zero-allocation serde helper for `Vec<u8>` raw byte buffers:
/// Encodes as compact CBOR Major Type 2 byte strings (`serialize_bytes`) instead of integer arrays.
pub mod serde_byte_vec {
    use serde::de::{Error as DeError, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    #[inline(always)]
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub(crate) struct ByteVecVisitor;

    impl<'de> Visitor<'de> for ByteVecVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a byte buffer")
        }

        #[inline]
        fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        #[inline]
        fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
            Ok(v.to_vec())
        }

        #[inline]
        fn visit_byte_buf<E: DeError>(self, v: Vec<u8>) -> Result<Self::Value, E> {
            Ok(v)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(65536));
            while let Some(b) = seq.next_element::<u8>()? {
                out.push(b);
            }
            Ok(out)
        }
    }

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_byte_buf(ByteVecVisitor)
    }
}

/// Zero-allocation serde helper for `Vec<([u8; 32], Vec<u8>)>` chunk transfer payloads
/// (`EpochWireMsg::FetchChunksResp`). Encodes both the 32-byte chunk hash and the compressed
/// chunk payload as compact CBOR Major Type 2 byte strings (`serialize_bytes`), eliminating
/// 1.91x integer-array wire bloat and per-byte loop overhead over QUIC.
pub mod serde_chunk_vec {
    use super::serde_byte_vec::ByteVecVisitor;
    use super::serde_bytes32::Bytes32Visitor;
    use serde::de::{SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::fmt;

    struct ByteSliceRef<'a>(&'a [u8]);

    impl Serialize for ByteSliceRef<'_> {
        #[inline(always)]
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    struct ChunkEntryRef<'a>(&'a [u8; 32], &'a [u8]);

    impl Serialize for ChunkEntryRef<'_> {
        #[inline(always)]
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            (ByteSliceRef(self.0), ByteSliceRef(self.1)).serialize(serializer)
        }
    }

    struct Hash32Elem([u8; 32]);

    impl<'de> Deserialize<'de> for Hash32Elem {
        #[inline]
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer
                .deserialize_bytes(Bytes32Visitor)
                .map(Hash32Elem)
        }
    }

    struct ByteVecElem(Vec<u8>);

    impl<'de> Deserialize<'de> for ByteVecElem {
        #[inline]
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer
                .deserialize_byte_buf(ByteVecVisitor)
                .map(ByteVecElem)
        }
    }

    pub type ChunkEntry = ([u8; 32], Vec<u8>);

    #[inline]
    pub fn serialize<S: Serializer>(
        chunks: &[ChunkEntry],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(chunks.len()))?;
        for (hash, data) in chunks {
            seq.serialize_element(&ChunkEntryRef(hash, data))?;
        }
        seq.end()
    }

    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<ChunkEntry>, D::Error> {
        struct ChunkVecVisitor;

        impl<'de> Visitor<'de> for ChunkVecVisitor {
            type Value = Vec<ChunkEntry>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a sequence of (32-byte hash, chunk byte buffer) pairs")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1024));
                while let Some((Hash32Elem(h), ByteVecElem(b))) = seq.next_element()? {
                    out.push((h, b));
                }
                Ok(out)
            }
        }

        deserializer.deserialize_seq(ChunkVecVisitor)
    }
}

/// Zero-copy `Arc<[u8]>` map serialization helper for `TargetChunkIndex`:
/// Encodes both 32-byte `Blake3Hash` keys and chunk byte buffers as compact CBOR major type 2
/// byte strings (`serialize_bytes`) instead of element-by-element integer sequences.
pub mod serde_arc_chunk_map {
    use super::serde_bytes32::Bytes32Visitor;
    use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::Arc;

    pub type ArcChunkMap = BTreeMap<[u8; 32], Arc<[u8]>>;

    struct ByteSliceRef<'a>(&'a [u8]);

    impl Serialize for ByteSliceRef<'_> {
        #[inline(always)]
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    pub fn serialize<S: Serializer>(map: &ArcChunkMap, serializer: S) -> Result<S::Ok, S::Error> {
        let mut m = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            m.serialize_entry(&ByteSliceRef(k), &ByteSliceRef(v))?;
        }
        m.end()
    }

    struct Hash32Key([u8; 32]);

    impl<'de> serde::Deserialize<'de> for Hash32Key {
        #[inline]
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer
                .deserialize_bytes(Bytes32Visitor)
                .map(Hash32Key)
        }
    }

    struct ArcBytesVal(Arc<[u8]>);

    impl<'de> serde::Deserialize<'de> for ArcBytesVal {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct ArcBytesVisitor;
            impl<'de> Visitor<'de> for ArcBytesVisitor {
                type Value = ArcBytesVal;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a chunk byte buffer")
                }
                #[inline]
                fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
                    Ok(ArcBytesVal(Arc::from(v)))
                }
                #[inline]
                fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                    Ok(ArcBytesVal(Arc::from(v)))
                }
                #[inline]
                fn visit_byte_buf<E: DeError>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                    Ok(ArcBytesVal(Arc::from(v.into_boxed_slice())))
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                    let mut buf = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                    while let Some(b) = seq.next_element::<u8>()? {
                        buf.push(b);
                    }
                    Ok(ArcBytesVal(Arc::from(buf.into_boxed_slice())))
                }
            }
            deserializer.deserialize_bytes(ArcBytesVisitor)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ArcChunkMap, D::Error> {
        struct ChunkMapVisitor;
        impl<'de> Visitor<'de> for ChunkMapVisitor {
            type Value = ArcChunkMap;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of 32-byte BLAKE3 hashes to chunk byte buffers")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((Hash32Key(k), ArcBytesVal(v))) = map.next_entry()? {
                    out.insert(k, v);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_map(ChunkMapVisitor)
    }
}
