{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
    nocargo = {
      url = "github:oxalica/nocargo";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { self, nixpkgs, flake-utils, nocargo, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        workspace = nocargo.lib.${system}.mkRustPackageOrWorkspace { src = self; };
      in
      rec {
        packages = {
          default = packages.resign;
          resign = workspace.release.resign.bin;
        };
      });
}
