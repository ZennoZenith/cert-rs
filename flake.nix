{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    naersk,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [
          (final: prev: {
            pebble = prev.pebble.overrideAttrs (old: rec {
              version = "2.10.0";

              src = prev.fetchFromGitHub {
                owner = "letsencrypt";
                repo = "pebble";
                rev = "v${version}";
                hash = "sha256-EMZ7grJU6dM+1o5NLPxDX/Yix8SOXHpGzNUULEYvREA=";
              };
            });
          })
        ];

        pkgs = import nixpkgs {
          inherit system overlays;
        };

        naersk' = pkgs.callPackage naersk {};
      in {
        packages.default = naersk'.buildPackage {
          src = ./.;
        };

        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustc
            cargo
            pkg-config
            pebble
            dig
          ];
        };
      }
    );
}
