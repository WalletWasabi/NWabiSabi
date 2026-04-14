{
  description = "WabiSabi anonymous credentials — C implementation";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfreePredicate = pkg:
            builtins.elem (nixpkgs.lib.getName pkg) [ "vscode" "vscode-with-extensions" ];
        };

        # Source filtered to exclude build artefacts not tracked by git
        src = pkgs.lib.cleanSourceWith {
          src    = ./.;
          filter = path: _type:
            # drop the build directory and any editor/nix noise
            !(builtins.elem (baseNameOf path) [ "build" "result" ".direnv" ]);
        };

        # secp256k1 v0.5.1 source — same version pinned in CMakeLists.txt
        secp256k1-src = pkgs.fetchFromGitHub {
          owner = "bitcoin-core";
          repo  = "secp256k1";
          rev   = "v0.5.1";
          hash  = "sha256-IYvvBob8e82EiPLX9yA8fd+KWrMri1rI5csp81rAdrg=";
        };

        # ------------------------------------------------------------------ #
        # Library + test package                                               #
        # ------------------------------------------------------------------ #
        wabisabi = pkgs.stdenv.mkDerivation {
          pname   = "wabisabi";
          version = "0.1.0";
          src     = src;

          nativeBuildInputs = [ pkgs.cmake ];

          # Run cmake manually so we control source/build dirs precisely.
          # The default Nix cmake hook gets confused with newer cmake versions.
          dontUseCmakeBuildDir = true;

          configurePhase = ''
            runHook preConfigure
            mkdir -p _build
            cmake -S . -B _build \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_SKIP_BUILD_RPATH=TRUE \
              -DCMAKE_SKIP_INSTALL_RPATH=TRUE \
              -DBUILD_SHARED_LIBS=OFF \
              -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
              "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1-src}"
            runHook postConfigure
          '';

          buildPhase = ''
            runHook preBuild
            cmake --build _build
            runHook postBuild
          '';

          # Run the test suite as part of the build.
          doCheck    = true;
          checkPhase = ''
            runHook preCheck
            ./_build/wabisabi_test
            runHook postCheck
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib $out/include $out/bin
            cp _build/libwabisabi.a  $out/lib/
            cp _build/wabisabi_test  $out/bin/
            cp -r include/*          $out/include/
            runHook postInstall
          '';
        };

        # ------------------------------------------------------------------ #
        # VS Code with C/C++ development extensions                            #
        # ------------------------------------------------------------------ #
        vscode-dev = pkgs.vscode-with-extensions.override {
          vscodeExtensions = with pkgs.vscode-extensions; [
            # Language server (IntelliSense, go-to-def, hover docs)
            llvm-vs-code-extensions.vscode-clangd
            # CMake syntax highlighting + language server integration
            twxs.cmake
            # CMake Tools: configure/build/test from the status bar
            ms-vscode.cmake-tools
            # Native debugger (uses LLDB under the hood — works on Linux/macOS)
            vadimcn.vscode-lldb
          ];
        };

      in
      {
        # nix build
        packages.default  = wabisabi;
        packages.wabisabi = wabisabi;

        # nix run — just execute the test binary
        apps.test = {
          type    = "app";
          program = "${wabisabi}/bin/wabisabi_test";
        };

        # nix check  (also runs during `nix build` via doCheck)
        checks.default = wabisabi;

        # nix develop
        devShells.default = pkgs.mkShell {
          name = "wabisabi-dev";

          packages = with pkgs; [
            # Build tools
            cmake
            ninja          # faster incremental builds; use: cmake -G Ninja
            gcc
            gdb            # GNU debugger
            clang-tools    # clangd, clang-format, clang-tidy

            # Convenience
            bear           # generate compile_commands.json for clangd
            gnumake

            # Editor
            vscode-dev
          ];

          # Point clangd to the compile_commands.json in the build directory.
          shellHook = ''
            export SECP256K1_SOURCE_DIR="${secp256k1-src}"

            echo ""
            echo "  WabiSabi C dev shell"
            echo "  ──────────────────────────────────────────────────"
            echo "  Configure:  cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \\"
            echo "                -DFETCHCONTENT_FULLY_DISCONNECTED=ON \\"
            echo "                -DFETCHCONTENT_SOURCE_DIR_SECP256K1=\$SECP256K1_SOURCE_DIR"
            echo "  Build:      cmake --build build"
            echo "  Test:       ./build/wabisabi_test"
            echo "  VS Code:    code ."
            echo ""

            # Generate compile_commands.json so clangd can resolve headers.
            if [ ! -f build/compile_commands.json ]; then
              cmake -B build -G Ninja \
                    -DCMAKE_BUILD_TYPE=Debug \
                    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
                    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
                    "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1-src}" \
                    -S . > /dev/null 2>&1 \
              && echo "  compile_commands.json generated in ./build/" \
              || echo "  (cmake configure skipped — run manually if needed)"
            fi
          '';
        };
      }
    );
}
