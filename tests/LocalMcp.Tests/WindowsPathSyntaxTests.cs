using LocalMcp.Security;

namespace LocalMcp.Tests;

public class WindowsPathSyntaxTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("..\\escape.txt")]
    [InlineData("folder\\..\\escape.txt")]
    [InlineData(@"C:\outside.txt")]
    [InlineData(@"\rooted")]
    [InlineData(@"\\server\share\file.txt")]
    [InlineData(@"\\?\C:\file.txt")]
    [InlineData(@"\\.\C:\file.txt")]
    [InlineData(@"\??\C:\file.txt")]
    [InlineData(@"\Device\HarddiskVolume1\file.txt")]
    [InlineData("file.txt:secret")]
    [InlineData("file.txt::$DATA")]
    [InlineData("folder/file.txt")]
    [InlineData(".\\file.txt")]
    [InlineData("folder\\.\\file.txt")]
    [InlineData("folder\\")]
    [InlineData("folder\\\\file.txt")]
    [InlineData("folder.\\file.txt")]
    [InlineData("folder \\file.txt")]
    [InlineData("CON")]
    [InlineData("aux.txt")]
    [InlineData("CONIN$")]
    [InlineData("COM¹.log")]
    [InlineData("file?.txt")]
    public void AlternateOrAmbiguousRelativePathForms_AreRejected(string? value)
    {
        Assert.False(WindowsRelativePath.TryParse(value, out _));
    }

    [Theory]
    [InlineData("file.txt")]
    [InlineData("directory\\file.txt")]
    [InlineData("PROJEC~1\\FILE.TXT")]
    public void OrdinaryAndShortAliasShapedRelativePaths_AreSyntacticallyAdmitted(string value)
    {
        Assert.True(WindowsRelativePath.TryParse(value, out var parsed));
        Assert.Equal(value, parsed!.Value);
    }
}
