namespace OmniDebug;

public record struct RuntimeReference(IntPtr Handle, string? Path);