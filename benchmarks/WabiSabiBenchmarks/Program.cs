using BenchmarkDotNet.Running;

namespace WabiSabiBenchmarks;

/// <summary>
/// Entry point. Run all benchmarks with:
///     dotnet run -c Release --project benchmarks/WabiSabiBenchmarks
/// or filter, e.g. only the full-protocol comparison:
///     dotnet run -c Release --project benchmarks/WabiSabiBenchmarks -- --filter '*FullProtocol*'
/// </summary>
public static class Program
{
    public static void Main(string[] args) =>
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
}
