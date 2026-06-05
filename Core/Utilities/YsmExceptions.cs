namespace YSMParser.Core.Utilities;

/// <summary>
/// Thrown when the YSM file has an unsupported or unrecognized format version.
/// </summary>
public class ParserUnSupportVersionException : Exception
{
    /// <inheritdoc />
    public override string Message => "Unsupported file version detected";
}

/// <summary>
/// Thrown when the YSM file has an invalid or corrupt file format structure.
/// </summary>
public class ParserInvalidFileFormatException : Exception
{
    /// <inheritdoc />
    public override string Message => "Unsupported file format detected";
}

/// <summary>
/// Thrown when the file integrity check fails, indicating data corruption.
/// </summary>
public class ParserCorruptedDataException : Exception
{
    /// <inheritdoc />
    public override string Message => "File Corrupted";
}

/// <summary>
/// Thrown when a buffer read exceeds available data, likely due to decryption failure.
/// </summary>
public class ParserIndexOutOfBoundException : Exception
{
    /// <inheritdoc />
    public override string Message => "Index Out Of Bound, Maybe Decryption Error";
}

/// <summary>
/// Thrown when an unexpected or unknown field is encountered during parsing.
/// </summary>
public class ParserUnknownFieldException : Exception
{
    /// <inheritdoc />
    public override string Message => "Unknown field encountered";
}

/// <summary>
/// Thrown when an unsupported or invalid file path is provided.
/// </summary>
public class ParserPathNotSupportedException : Exception
{
    /// <inheritdoc />
    public override string Message => "Path not supported";
}
