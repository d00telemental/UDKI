namespace UDKI.Core;


/// <summary>
/// Marks an Unreal-reflected class.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, AllowMultiple = false, Inherited = true)]
public class UClassAttribute(string name, int fixedSize) : Attribute
{
    /// <summary>
    /// Reflected name of the class, can be different from managed class's name.
    /// </summary>
    public string Name { get; private set; } = name;
    /// <summary>
    /// Number of bytes an instance of this class occupies.
    /// </summary>
    public int FixedSize { get; private set; } = fixedSize;
}

/// <summary>
/// Marks a field in a possibly-reflected type.
/// </summary>
[AttributeUsage(AttributeTargets.Field, AllowMultiple = false, Inherited = false)]
public class UFieldAttribute(string name, int fixedOffset) : Attribute
{
    /// <summary>
    /// Reflected name of the field, can be different from managed field's name.
    /// </summary>
    public string Name { get; private set; } = name;
    /// <summary>
    /// Number of bytes from start of a class instance to this field.
    /// </summary>
    public int FixedOffset { get; private set; } = fixedOffset;

    /// <summary>
    /// Sets whether this string should be marshalled as FName, not as FString.
    /// </summary>
    public bool AsFName { get; set; } = false;
}
