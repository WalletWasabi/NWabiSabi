using Newtonsoft.Json;
using System.Collections.Generic;

namespace WabiSabi.Tests.Crypto;

public class StrobeTestVector
{
	[JsonConstructor]
	public StrobeTestVector(string name, List<StrobeOperation> operations)
	{
		Name = name;
		Operations = operations;
	}

	[JsonProperty(PropertyName = "name")]
	public string Name { get; }

	[JsonProperty(PropertyName = "operations")]
	public List<StrobeOperation> Operations { get; }
}
