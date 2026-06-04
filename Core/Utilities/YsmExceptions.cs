namespace YSMParser.Core.Utilities;

public class ParserUnSupportVersionException : Exception
{
    public override string Message => "Unsupported file version detected";
}

public class ParserInvalidFileFormatException : Exception
{
    public override string Message => "Unsupported file format detected";
}

public class ParserCorruptedDataException : Exception
{
    public override string Message => "File Corrupted";
}

public class ParserIndexOutOfBoundException : Exception
{
    public override string Message => "Index Out Of Bound, Maybe Decryption Error";
}

public class ParserUnknownFieldException : Exception
{
    public override string Message => "Unknown field encountered";
}

public class ParserPathNotSupportedException : Exception
{
    public override string Message => "Path not supported";
}
