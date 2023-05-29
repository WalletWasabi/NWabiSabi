using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using WabiSabi.Crypto.ZeroKnowledge;

namespace WabiSabi.Native;

public static class Interop
{
	[UnmanagedCallersOnly]
	public static unsafe int CreateRequestForZeroAmount(
		[In] NativeCreateRequestParameters* parameters,
		[Out] NativeCredentialRequestData* request)
	{
		return CreateRequestForZeroAmount(
			Unsafe.AsRef<NativeCreateRequestParameters>(parameters),
			out Unsafe.AsRef<NativeCredentialRequestData>(request));
	}
	
	public static int CreateRequestForZeroAmount(
		in NativeCreateRequestParameters parameters,
		out NativeCredentialRequestData request)
	{
		try
		{
			var client = CreateClient(parameters);
			var result = client.CreateRequestForZeroAmount();

			request = new()
			{
				Request = NativeCredentialsRequest.FromManaged(result.CredentialsRequest),
				Validation = NativeCredentialsResponseValidation.FromManaged(result.CredentialsResponseValidation)
			};

			return 0;
		}
		catch (Exception e)
		{
			Unsafe.SkipInit(out request);
			return e.HResult;
		}
	}

	[UnmanagedCallersOnly]
	public static unsafe int CreateRequest(
		[In] NativeCreateRequestParameters* parameters,
		NativeArray<long> amounts,
		NativeArray<NativeCredential> credentials,
		[Out] NativeCredentialRequestData* request)
	{
		return CreateRequest(
			Unsafe.AsRef<NativeCreateRequestParameters>(parameters),
			amounts,
			credentials,
			out Unsafe.AsRef<NativeCredentialRequestData>(request));
	}

	public static int CreateRequest(
		in  NativeCreateRequestParameters parameters,
		NativeArray<long> amounts,
		NativeArray<NativeCredential> credentials,
		out NativeCredentialRequestData request)
	{
		try
		{
			var credentialsSpan = credentials.AsSpan();
			var credentialsArray = new Credential[credentialsSpan.Length];

			for (var index = 0; index < credentialsSpan.Length; index += 1)
			{
				ref var credential = ref credentialsSpan[index];
				
				credentialsArray[index] = NativeCredential.ToManaged(credentialsSpan[index]);
			}

			var client = CreateClient(parameters);
			var result = client.CreateRequest(amounts.AsSpan().ToArray(), credentialsArray, CancellationToken.None);

			request = new()
			{
				Request = NativeCredentialsRequest.FromManaged(result.CredentialsRequest),
				Validation = NativeCredentialsResponseValidation.FromManaged(result.CredentialsResponseValidation)
			};

			return 0;
		}
		catch (Exception e)
		{
			Unsafe.SkipInit(out request);
 			return e.HResult;
		}
	}

	[UnmanagedCallersOnly]
	public static unsafe int HandleResponse(
		[In] NativeCreateRequestParameters* parameters,
		[In] NativeCredentialsResponse* response,
		[In] NativeCredentialsResponseValidation* validation,
		[Out] NativeArray<NativeCredential>* credentials)
	{
		return HandleResponse(
			Unsafe.AsRef<NativeCreateRequestParameters>(parameters),
			Unsafe.AsRef<NativeCredentialsResponse>(response),
			Unsafe.AsRef<NativeCredentialsResponseValidation>(validation),
			out Unsafe.AsRef<NativeArray<NativeCredential>>(credentials));
	}
	
	public static unsafe int HandleResponse(
		in NativeCreateRequestParameters parameters,
		in NativeCredentialsResponse response,
		in NativeCredentialsResponseValidation validation,
		out NativeArray<NativeCredential> credentials)
	{
		try
		{
			var client = CreateClient(Unsafe.AsRef<NativeCreateRequestParameters>(parameters));
			var result = client
				.HandleResponse(
					NativeCredentialsResponse.ToManaged(Unsafe.AsRef<NativeCredentialsResponse>(response)),
					NativeCredentialsResponseValidation.ToManaged(Unsafe.AsRef<NativeCredentialsResponseValidation>(validation)))
				.ToArray();

			credentials = NativeArray.FromManaged(result, static credential => NativeCredential.FromManaged(credential));
			
			return 0;
		}
		catch (Exception e)
		{
			Unsafe.SkipInit(out credentials);
			return e.HResult;
		}
	}

	[UnmanagedCallersOnly]
	public static unsafe void FreeRequest([In] NativeCredentialRequestData* request)
	{
		FreeRequest(ref Unsafe.AsRef<NativeCredentialRequestData>(request));
	}
	
	public static unsafe void FreeRequest(ref NativeCredentialRequestData request)
	{
		if (!Unsafe.IsNullRef(ref request))
		{
			foreach (var requested in request.Request.Requested.AsSpan())
			{
				Free(requested.BitCommitments.Data);
			}

			foreach (var proof in request.Request.Proofs.AsSpan())
			{
				Free(proof.PublicNonces.Data);
				Free(proof.Responses.Data);
			}
			
			Free(request.Request.Presented.Data);
			Free(request.Request.Requested.Data);
			Free(request.Request.Proofs.Data);

			Free(request.Validation.Presented.Data);
			Free(request.Validation.Requested.Data);
		}

		static void Free<T>(T* value)
			where T : unmanaged
		{
			if (value is not null)
			{
				Marshal.FreeHGlobal(new IntPtr(value));
			}
		}
	}

	private static WabiSabiClient CreateClient(in NativeCreateRequestParameters parameters)
	{
		var randomNumberGenerator = SecureRandom.Instance;
		var credentialParameters = new CredentialIssuerParameters(
			NativeGroupElement.ToManaged(parameters.Cw),
			NativeGroupElement.ToManaged(parameters.I));

		return new WabiSabiClient(
			credentialParameters,
			randomNumberGenerator,
			parameters.RangeProofUpperBound);
	}
	
	internal static void SetField<T>(in T field, in T value)
		where T : unmanaged
	{
		Unsafe.AsRef(field) = value;
	}
}
