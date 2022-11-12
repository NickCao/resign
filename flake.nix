{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let pkgs = import nixpkgs { inherit system; }; in
      with pkgs; rec {
        devShell = mkShell {
          nativeBuildInputs = [ rust-analyzer rustfmt clippy ];
          inputsFrom = [ packages.default ];
        };
        packages = {
          default = packages.resign;
          resign = rustPlatform.buildRustPackage {
            name = "resign";
            src = self;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            nativeBuildInputs = [ pkg-config cmake rustPlatform.bindgenHook ];
            buildInputs = [ nettle pcsclite ];
            doCheck = false;
          };
        };
      });
}
