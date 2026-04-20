{
  description = "WabiSabi anonymous credentials — C and C# implementations";

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

        # secp256k1 v0.5.1 source — same version pinned in c/CMakeLists.txt
        secp256k1-src = pkgs.fetchFromGitHub {
          owner = "bitcoin-core";
          repo  = "secp256k1";
          rev   = "v0.5.1";
          hash  = "sha256-IYvvBob8e82EiPLX9yA8fd+KWrMri1rI5csp81rAdrg=";
        };

        # C source filtered to exclude build artefacts
        c-src = pkgs.lib.cleanSourceWith {
          src    = ./c;
          filter = path: _type:
            !(builtins.elem (baseNameOf path) [ "build" "result" ".direnv" ]);
        };

        # Repo source filtered to relevant .NET + C# files
        dotnet-src = pkgs.lib.cleanSourceWith {
          src    = ./.;
          filter = path: _type:
            !(builtins.elem (baseNameOf path) [ "build" "result" ".direnv" "obj" "bin" ]);
        };

        # ------------------------------------------------------------------ #
        # C library: host build (linux-x64) with tests                        #
        # ------------------------------------------------------------------ #
        wabisabi-c = pkgs.stdenv.mkDerivation {
          pname   = "wabisabi-c";
          version = "0.1.0";
          src     = c-src;

          nativeBuildInputs = [ pkgs.cmake ];
          dontUseCmakeBuildDir = true;

          configurePhase = ''
            runHook preConfigure
            mkdir -p _build
            cmake -S . -B _build \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_SKIP_BUILD_RPATH=TRUE \
              -DCMAKE_SKIP_INSTALL_RPATH=TRUE \
              -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
              "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1-src}"
            runHook postConfigure
          '';

          buildPhase = ''
            runHook preBuild
            cmake --build _build
            runHook postBuild
          '';

          doCheck    = true;
          checkPhase = ''
            runHook preCheck
            LD_LIBRARY_PATH=_build:_build/_deps/secp256k1-build/src ./_build/wabisabi_test
            runHook postCheck
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib $out/include $out/bin
            cp _build/libwabisabi.so    $out/lib/
            cp _build/wabisabi_test     $out/bin/
            cp -r include/*             $out/include/
            runHook postInstall
          '';
        };

        # ------------------------------------------------------------------ #
        # C library: cross-compiled shared libraries (no tests)               #
        # ------------------------------------------------------------------ #

        # Build only the shared library for a given package set (no test binary).
        # cmake always runs on the host; only the compiler and linker are cross.
        buildWabiSabiCross = crossPkgs: crossPkgs.stdenv.mkDerivation {
          pname   = "wabisabi-c";
          version = "0.1.0";
          src     = c-src;

          nativeBuildInputs = [ pkgs.cmake ];
          dontUseCmakeBuildDir = true;

          configurePhase = ''
            runHook preConfigure
            mkdir -p _build
            cmake -S . -B _build \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_SKIP_BUILD_RPATH=TRUE \
              -DCMAKE_SKIP_INSTALL_RPATH=TRUE \
              -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
              "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1-src}"
            runHook postConfigure
          '';

          buildPhase = ''
            runHook preBuild
            cmake --build _build --target wabisabi
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib
            # Linux/macOS uses lib prefix; Windows (mingw) does not
            cp _build/libwabisabi.so    $out/lib/ 2>/dev/null || \
            cp _build/libwabisabi.dylib $out/lib/ 2>/dev/null || \
            cp _build/wabisabi.dll      $out/lib/ 2>/dev/null || \
            (echo "No shared library found in _build/"; ls _build/; exit 1)
            runHook postInstall
          '';
        };

        wabisabi-c-linux-arm64 = buildWabiSabiCross pkgs.pkgsCross.aarch64-multiplatform;
        wabisabi-c-win64       = buildWabiSabiCross pkgs.pkgsCross.mingwW64;

        # ------------------------------------------------------------------ #
        # NuGet package: WabiSabi.Native (C# wrappers + native shared libs)  #
        # ------------------------------------------------------------------ #
        wabisabi-nuget = pkgs.buildDotnetModule {
          pname   = "WabiSabi.Native";
          version = "0.1.0";
          src     = dotnet-src;

          projectFile = "csharp/WabiSabi.Native/WabiSabi.Native.csproj";
          nugetDeps   = ./csharp/WabiSabi.Native/nuget-deps.nix;

          dotnet-sdk = pkgs.dotnetCorePackages.sdk_10_0;

          # Populate runtimes/ with all available platform binaries before packing.
          # linux-x64 and linux-arm64 are always built; win-x64 via mingw cross-compile.
          # osx-x64/osx-arm64 require a macOS build host (no macOS SDK in nixpkgs).
          preBuild = ''
            mkdir -p csharp/WabiSabi.Native/runtimes/linux-x64/native
            cp ${wabisabi-c}/lib/libwabisabi.so \
               csharp/WabiSabi.Native/runtimes/linux-x64/native/libwabisabi.so

            mkdir -p csharp/WabiSabi.Native/runtimes/linux-arm64/native
            cp ${wabisabi-c-linux-arm64}/lib/libwabisabi.so \
               csharp/WabiSabi.Native/runtimes/linux-arm64/native/libwabisabi.so

            mkdir -p csharp/WabiSabi.Native/runtimes/win-x64/native
            cp ${wabisabi-c-win64}/lib/wabisabi.dll \
               csharp/WabiSabi.Native/runtimes/win-x64/native/wabisabi.dll
          '' + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
            mkdir -p csharp/WabiSabi.Native/runtimes/osx-x64/native
            cp ${wabisabi-c}/lib/libwabisabi.dylib \
               csharp/WabiSabi.Native/runtimes/osx-x64/native/libwabisabi.dylib
          '';

          buildPhase = ''
            runHook preBuild
            dotnet pack csharp/WabiSabi.Native/WabiSabi.Native.csproj \
              --no-restore \
              -c Release \
              -o $out
            runHook postBuild
          '';

          # dotnet pack writes directly to $out; nothing left to install.
          installPhase = "true";

          # Expose a script that regenerates nuget-deps.nix when dependencies change:
          #   nix build .#wabisabi-nuget.passthru.fetch-deps && ./result csharp/WabiSabi.Native/nuget-deps.nix
        };

        # .NET runtime libs needed on Linux for dotnet to work
        dotnetLibs = with pkgs; [
          xorg.libX11
          xorg.libICE
          xorg.libSM
          fontconfig.lib
          zlib
          stdenv.cc.cc.lib
          openssl
        ];

        # ------------------------------------------------------------------ #
        # VS Code with C/C++ development extensions                            #
        # ------------------------------------------------------------------ #
        vscode-dev = pkgs.vscode-with-extensions.override {
          vscodeExtensions = with pkgs.vscode-extensions; [
            llvm-vs-code-extensions.vscode-clangd
            twxs.cmake
            ms-vscode.cmake-tools
            vadimcn.vscode-lldb
            vscodevim.vim
            ms-vscode.hexeditor
          ];
        };

      in
      {
        # nix build              →  builds the C library, FFI shared lib, and test binary
        # nix build .#wabisabi-nuget  →  produces WabiSabi.Native.0.1.0.nupkg
        packages.default       = wabisabi-c;
        packages.wabisabi-c    = wabisabi-c;
        packages.wabisabi-nuget = wabisabi-nuget;

        # nix run  →  execute the C test suite
        apps.test = {
          type    = "app";
          program = "${wabisabi-c}/bin/wabisabi_test";
        };

        # nix check  (also runs during `nix build` via doCheck)
        checks.default = wabisabi-c;

        devShells = {
          # nix develop .#c  →  C development (mirrors c/flake.nix devShell)
          c = pkgs.mkShell {
            name = "wabisabi-c-dev";

            packages = with pkgs; [
              cmake
              ninja
              gcc
              gdb
              clang-tools
              bear
              gnumake
              vscode-dev
            ];

            shellHook = ''
              export SECP256K1_SOURCE_DIR="${secp256k1-src}"

              echo ""
              echo "  WabiSabi C dev shell"
              echo "  ──────────────────────────────────────────────────"
              echo "  Configure:  cmake -B c/build -G Ninja -DCMAKE_BUILD_TYPE=Debug \\"
              echo "                -DFETCHCONTENT_FULLY_DISCONNECTED=ON \\"
              echo "                -DFETCHCONTENT_SOURCE_DIR_SECP256K1=\$SECP256K1_SOURCE_DIR \\"
              echo "                -S c"
              echo "  Build:      cmake --build c/build"
              echo "  Test:       ./c/build/wabisabi_test"
              echo ""

              if [ ! -f c/build/compile_commands.json ]; then
                cmake -B c/build -G Ninja \
                      -DCMAKE_BUILD_TYPE=Debug \
                      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
                      -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
                      "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1-src}" \
                      -S c > /dev/null 2>&1 \
                && echo "  compile_commands.json generated in ./c/build/" \
                || echo "  (cmake configure skipped — run manually if needed)"
              fi
            '';
          };

          # nix develop .#dotnet  →  .NET / C# development
          dotnet = pkgs.mkShell {
            name = "wabisabi-dotnet-dev";

            packages = with pkgs; [
              dotnet-sdk_10
            ];

            buildInputs = dotnetLibs;

            DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = 1;

            shellHook = ''
              export LD_LIBRARY_PATH="$PWD/c/build:${pkgs.lib.makeLibraryPath dotnetLibs}"
              echo ""
              echo "  WabiSabi .NET dev shell"
              echo "  ──────────────────────────────────────────────────"
              echo "  Build:   dotnet build csharp/WabiSabi.sln"
              echo "  Test:    dotnet test  csharp/WabiSabi.sln"
              echo ""
            '';
          };

          # nix develop  →  combined C + .NET shell for interop work
          default = pkgs.mkShell {
            name = "wabisabi-dev";

            packages = with pkgs; [
              # C tools
              cmake
              ninja
              gcc
              gdb
              clang-tools
              bear
              gnumake
              # .NET tools
              dotnet-sdk_10
            ];

            buildInputs = dotnetLibs;

            DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = 1;

            shellHook = ''
              export LD_LIBRARY_PATH="$PWD/c/build:${pkgs.lib.makeLibraryPath dotnetLibs}"
              export SECP256K1_SOURCE_DIR="${secp256k1-src}"

              echo ""
              echo "  WabiSabi dev shell  (C + .NET)"
              echo "  ──────────────────────────────────────────────────"
              echo "  C build:    cmake -B c/build -G Ninja -DCMAKE_BUILD_TYPE=Debug \\"
              echo "                -DFETCHCONTENT_FULLY_DISCONNECTED=ON \\"
              echo "                -DFETCHCONTENT_SOURCE_DIR_SECP256K1=\$SECP256K1_SOURCE_DIR \\"
              echo "                -S c  &&  cmake --build c/build"
              echo "  C test:     ./c/build/wabisabi_test"
              echo "  .NET build: dotnet build csharp/WabiSabi.sln"
              echo "  .NET test:  dotnet test  csharp/WabiSabi.sln"
              echo "  Interop:    dotnet run --project interop/WabiSabiInterop.csproj"
              echo ""

              if [ ! -f c/build/compile_commands.json ]; then
                cmake -B c/build -G Ninja \
                      -DCMAKE_BUILD_TYPE=Debug \
                      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
                      -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
                      "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=${secp256k1-src}" \
                      -S c > /dev/null 2>&1 \
                && echo "  compile_commands.json generated in ./c/build/" \
                || echo "  (cmake configure skipped — run manually if needed)"
              fi
            '';
          };
        };
      }
    );
}
