namespace OmniDebug.Interactive;

public class TokenizerTests
{
    [Fact]
    public void CanTokenizeEmptyString()
    {
        var tokens = Tokenizer.Tokenize("");
        Assert.Empty(tokens);
    }
    
    [Theory]
    [InlineData("\"hello\"", "hello")]
    [InlineData("\"he\\\"llo\"", "he\"llo")]
    [InlineData("\"he\"llo", "hello")]
    [InlineData("a\"hello world\"b", "ahello worldb")]
    public void CanTokenizeQuotedStrings(string input, string expected)
    {
        var tokens = Tokenizer.Tokenize(input);
        Assert.NotEmpty(tokens);
        Assert.Equal(expected, tokens[0]);
    }
    
    [Theory]
    [InlineData("-hello")]
    [InlineData("--hello")]
    [InlineData("/hello")]
    public void CanTokenizeSwitches(string input)
    {
        var tokens = Tokenizer.Tokenize(input);
        Assert.Single(tokens);
        Assert.Equal(input, tokens[0]);
    }
    
    [Theory]
    [InlineData("hello")]
    [InlineData("hello-world")]
    [InlineData("hello_this_is!a_test_of?word_parsing")]
    public void CanTokenizeWords(string input)
    {
        var tokens = Tokenizer.Tokenize(input);
        Assert.Single(tokens);
        Assert.Equal(input, tokens[0]);
    }
    
    [Fact]
    public void CanTokenizeFullCommand()
    {
        const string input =
            @"target attach --process-id 12345 --remote-debugging-port=1234 ""wowy zowy"" --launch-command=""this is \""pretty\"" cool""";
        var tokens = Tokenizer.Tokenize(input);
        Assert.Equal(
            new [] { "target", "attach", "--process-id", "12345", "--remote-debugging-port=1234", "wowy zowy", "--launch-command=this is \"pretty\" cool" },
            tokens);
    }
}