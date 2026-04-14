using System;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NBitcoin.Secp256k1;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Groups;
using WabiSabi.Crypto.Randomness;


namespace WabiSabi.Native;

// dotnet publish /p:NativeLib=Static -c Release -r linux-x64 --self-contained

public static class NativeInterface
{
    [StructLayout(LayoutKind.Sequential)]
    public struct FE_ 
    {
        public readonly uint n0, n1, n2, n3, n4, n5, n6, n7, n8, n9;

        public FE_(uint n0, uint n1, uint n2, uint n3, uint n4, uint n5, uint n6, uint n7, uint n8, uint n9)
        {
            this.n0 = n0;
            this.n1 = n1;
            this.n2 = n2;
            this.n3 = n3;
            this.n4 = n4;
            this.n5 = n5;
            this.n6 = n6;
            this.n7 = n7;
            this.n8 = n8;
            this.n9 = n9;
        }

        public static implicit operator FE_ (FE fe) =>
            new (fe.n0, fe.n1, fe.n2, fe.n3, fe.n4, fe.n5, fe.n6, fe.n7, fe.n8, fe.n9);

        public static implicit operator FE (FE_ fe) =>
            new (fe.n0, fe.n1, fe.n2, fe.n3, fe.n4, fe.n5, fe.n6, fe.n7, fe.n8, fe.n9);
    }

    
    [StructLayout(LayoutKind.Sequential)]
    public struct GE_
    {
        public readonly FE_ x;
        public readonly FE_ y;
        public readonly bool infinity;
        
        private GE_(FE_ x, FE_ y, bool infinity)
        {
            this.x = x;
            this.y = y;
            this.infinity = infinity;
        }

        public static implicit operator GE_ (GE ge) =>
            new(ge.x, ge.y, ge.infinity);

        public static implicit operator GE (GE_ ge) =>
            new(ge.x, ge.y, ge.infinity);
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct CredentialIssuerParameters_
    {
        public readonly GE_ Cw;
        public readonly GE_ I;

        private CredentialIssuerParameters_(GE_ cw, GE_ i)
        {
            Cw = cw;
            I = i;
        }
        
        public static implicit operator CredentialIssuerParameters_ (CredentialIssuerParameters issuerParameters) =>
            new(issuerParameters.Cw.Ge, issuerParameters.I.Ge);

        public static implicit operator CredentialIssuerParameters (CredentialIssuerParameters_ issuerParameters) =>
            new(new GroupElement(issuerParameters.Cw), new GroupElement(issuerParameters.I));
        
    }
    
    [NativeCallable(EntryPoint = "createRequestForZeroAmount", CallingConvention = CallingConvention.Cdecl)]
    public static int CreateRequestForZeroAmount(CredentialIssuerParameters_ issuerParameters)
    {
        var client = new WabiSabiClient(issuerParameters, SecureRandom.Instance, 100_000_000);
        var r = client.CreateRequestForZeroAmount();
        return 0;
    }

    [RuntimeExport("test")]
    public static FE_ TestFunction()
    {
        return new FE_(0,1,2,3,4,5,6,7,8,9);
    }

    [RuntimeExport("testsegfault")]
    public static FE_ TestSegfault()
    {
        return EC.G.x;
    }
    
    
    [RuntimeExport("testint")]
    public static int Test1Function()
    {
        return 7;
    }
}