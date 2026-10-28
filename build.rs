use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Link libzstd and libsqlite3 when present in the environment or Nix store
    println!("cargo:rustc-link-lib=dylib=zstd");
    println!("cargo:rustc-link-lib=dylib=sqlite3");

    if let Ok(ld_path) = env::var("LD_LIBRARY_PATH") {
        for dir in ld_path.split(':').filter(|s| !s.is_empty()) {
            if Path::new(dir).exists() {
                println!("cargo:rustc-link-search=native={dir}");
                println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
            }
        }
    }

    // Fallback well-known Nix store paths from the locked flake inputs if LD_LIBRARY_PATH isn't set
    let fallback_dirs = [
        "/nix/store/f5r77q40xh7rj30dfkajv8y6jwbf4xh2-zstd-1.5.7/lib",
        "/nix/store/00qn3vc7r4m32c072kjnrbxd86w9slzj-zstd-1.5.7/lib",
        "/nix/store/xrzzvmqkmx68f6yj1hy16gjvc1r2bmr8-sqlite-3.53.3/lib",
        "/nix/store/1c3zr8jpxrhylqg52v5b5bl7vjys5dh8-sqlite-3.53.4/lib",
    ];
    for dir in fallback_dirs {
        if Path::new(dir).exists() {
            println!("cargo:rustc-link-search=native={dir}");
            println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
        }
    }

    // Optional Tracy 0.14.1 C client library integration (from github:Quince-Pie/tracy-flake)
    println!("cargo:rerun-if-env-changed=TRACY_CLIENT_LIB");
    if env::var_os("CARGO_FEATURE_TRACY").is_some() {
        println!("cargo:rustc-link-lib=dylib=TracyClient");
        if let Ok(tracy_dir) = env::var("TRACY_CLIENT_LIB")
            && Path::new(&tracy_dir).exists()
        {
            println!("cargo:rustc-link-search=native={tracy_dir}");
            println!("cargo:rustc-link-arg=-Wl,-rpath,{tracy_dir}");
        }
        let tracy_dirs = [
            "/nix/store/gynxaprr40k4j3w2mavsb8xqyzrj442i-tracy-client-0.14.1/lib",
            "/nix/store/j159sx9y0qcf7ckha981ibfnrgbj04m0-tracy-0.14.1-lib/lib",
        ];
        for dir in tracy_dirs {
            if Path::new(dir).exists() {
                println!("cargo:rustc-link-search=native={dir}");
                println!("cargo:rustc-link-arg=-Wl,-rpath,{dir}");
            }
        }
    }
}
