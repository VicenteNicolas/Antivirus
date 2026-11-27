using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SentinelSecurity.Engine;

public static class ExecutableTrust
{
    private static readonly Guid AuthenticodePolicy = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustESubjectFormUnknown = unchecked((int)0x800B0003);
    private const int TrustEProviderUnknown = unchecked((int)0x800B0001);
    private const uint NoUi = 2;
    private const uint FileChoice = 1;
    private const uint CatalogChoice = 2;
    private const uint CacheOnly = 0x1000;
    private const uint DisableLegacyHashes = 0x2000;

    public static TrustResult Inspect(string path)
    {
        if (!OperatingSystem.IsWindows())
            return TrustResult.Unavailable;

        var original = Verify(new WinTrustFile
        {
            Size = (uint)Marshal.SizeOf<WinTrustFile>(),
            FilePath = path
        }, FileChoice);

        return original switch
        {
            0 => TrustResult.Trusted,
            TrustENoSignature => InspectCatalog(path),
            TrustESubjectFormUnknown or TrustEProviderUnknown => TrustResult.Unavailable,
            _ => TrustResult.Unverified
        };
    }

    private static TrustResult InspectCatalog(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
                return TrustResult.Unavailable;
            try
            {
                var hash = new byte[32];
                uint length = (uint)hash.Length;
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, stream.SafeFileHandle, ref length, hash, 0) || length != hash.Length)
                    return TrustResult.Unavailable;
                var catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, length, 0, IntPtr.Zero);
                if (catalog == IntPtr.Zero)
                    return TrustResult.NoEmbeddedSignature;
                try
                {
                    var info = new CatalogInfo { Size = (uint)Marshal.SizeOf<CatalogInfo>() };
                    if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0)) return TrustResult.Unavailable;
                    var signed = new WinTrustCatalog
                    {
                        Size = (uint)Marshal.SizeOf<WinTrustCatalog>(),
                        CatalogPath = info.CatalogPath,
                        MemberTag = Convert.ToHexString(hash),
                        MemberPath = path,
                        Admin = admin
                    };
                    return Verify(signed, CatalogChoice) == 0 ? TrustResult.Trusted : TrustResult.Unverified;
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); }
            }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }
        catch (Exception error) when (ScanPath.Expected(error))
        {
            return TrustResult.Unavailable;
        }
    }

    private static int Verify<T>(T subject, uint choice) where T : struct
    {
        var subjectPointer = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        var initialized = false;
        try
        {
            Marshal.StructureToPtr(subject, subjectPointer, false);
            initialized = true;
            var data = new WinTrustData
            {
                Size = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = NoUi,
                UnionChoice = choice,
                Subject = subjectPointer,
                ProviderFlags = CacheOnly | DisableLegacyHashes
            };
            var action = AuthenticodePolicy;
            return WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
        finally
        {
            if (initialized) Marshal.DestroyStructure<T>(subjectPointer);
            Marshal.FreeHGlobal(subjectPointer);
        }
    }

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WinTrustData data);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string algorithm, IntPtr policy, uint flags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle fileHandle, ref uint length,
        [Out] byte[] hash, uint flags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint length, uint flags, IntPtr previous);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("wintrust.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFile
    {
        public uint Size;
        public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint Size;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string CatalogPath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalog
    {
        public uint Size;
        public uint Version;
        public string CatalogPath;
        public string MemberTag;
        public string MemberPath;
        public IntPtr FileHandle;
        public IntPtr CalculatedHash;
        public uint CalculatedHashLength;
        public IntPtr CatalogContext;
        public IntPtr Admin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint Size;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr Subject;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }
}

public enum TrustResult
{
    Unavailable,
    Trusted,
    NoEmbeddedSignature,
    Unverified
}
