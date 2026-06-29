# NuGet dependency lock file for WabiSabi.csproj.
# Consumed by buildDotnetModule in flake.nix.
#
# To regenerate after a dependency change:
#   nix build .#packages.x86_64-linux.wabisabi-nuget.passthru.fetch-deps
#   ./result csharp/WabiSabi/nuget-deps.nix
{ fetchNuGet }: [
  (fetchNuGet {
    pname   = "NBitcoin.Secp256k1";
    version = "3.1.0";
    hash    = "sha256-vhp1Rjl//09c8U912Mqfu6/Ip0/ljnZkCkDo9k45dtU=";
  })
]
