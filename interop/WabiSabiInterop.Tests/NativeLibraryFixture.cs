using System;
using WabiSabi.Native;
using Xunit;

namespace WabiSabiInterop.Tests;

/// <summary>
/// xUnit collection fixture that calls <see cref="NativeWabi.Init"/> once
/// before any test in the collection runs and <see cref="NativeWabi.Cleanup"/>
/// once after all tests complete.
/// </summary>
public sealed class NativeLibraryFixture : IDisposable
{
    public NativeLibraryFixture() => NativeWabi.Init();

    public void Dispose() => NativeWabi.Cleanup();
}

[CollectionDefinition("NativeLibrary")]
public class NativeLibraryCollection : ICollectionFixture<NativeLibraryFixture> { }
