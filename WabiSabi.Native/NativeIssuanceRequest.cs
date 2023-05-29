namespace WabiSabi.Native;

public struct NativeIssuanceRequest
{
	public NativeGroupElement Ma;
	public NativeArray<NativeGroupElement> BitCommitments;

	internal static NativeIssuanceRequest FromManaged(IssuanceRequest managed) => new()
	{
		Ma = NativeGroupElement.FromManaged(managed.Ma),
		BitCommitments = NativeArray.FromManaged(managed.BitCommitments, NativeGroupElement.FromManaged)
	};
}
