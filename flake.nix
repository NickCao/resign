{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
    registry-crates-io = { url = "github:rust-lang/crates.io-index"; flake = false; };
    nocargo = {
      url = "github:oxalica/nocargo";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.registry-crates-io.follows = "registry-crates-io";
    };
  };
  outputs = { self, nixpkgs, flake-utils, nocargo, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        workspace = nocargo.lib.${system}.mkRustPackageOrWorkspace {
          src = self;
          buildCrateOverrides = with nixpkgs.legacyPackages.${system}; {
            # Use package id format `pkgname version (registry)` to reference a direct or transitive dependency.
            "nettle-sys 2.1.0 (registry+https://github.com/rust-lang/crates.io-index)" = old: {
              nativeBuildInputs = [ pkg-config rustPlatform.bindgenHook ];
              propagatedBuildInputs = [ nettle ];
            };
            "pcsc-sys 1.2.0 (registry+https://github.com/rust-lang/crates.io-index)" = old: {
              nativeBuildInputs = [ pkg-config ];
              propagatedBuildInputs = [ pcsclite ];
            };
          };
        };
      in
      rec {
        packages = {
          default = packages.resign;
          resign = workspace.release.resign.bin;
        };
      });
}
