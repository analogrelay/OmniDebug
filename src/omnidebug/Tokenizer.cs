using System.Text;

namespace OmniDebug.Interactive;

internal static class Tokenizer
{
    public static IReadOnlyList<string> Tokenize(string line) => Tokenize(line.AsSpan());
    
    public static IReadOnlyList<string> Tokenize(ReadOnlySpan<char> line)
    {
        static string ReadWord(ref ReadOnlySpan<char> input, TokenType tokenType)
        {
            var output = new StringBuilder();
            while(input.Length > 0)
            {
                if (input[0] == '"')
                {
                    ReadQuoted(ref input, output);
                }
                else if (char.IsWhiteSpace(input[0]))
                {
                    break;
                }
                else
                {
                    output.Append(input[0]);
                    input = input[1..];
                }
            }

            return output.ToString();
        }

        static void ReadQuoted(ref ReadOnlySpan<char> input, StringBuilder output)
        {
            var escaping = false;
            input = input[1..];
            while(input.Length > 0)
            {
                if (input[0] == '"')
                {
                    if (escaping)
                    {
                        escaping = false;
                    }
                    else
                    {
                        input = input[1..];
                        return;
                    }
                }
                else if (escaping)
                {
                    throw new FormatException($"Unrecognizded escape sequence '\\{input[0]}'");
                }
                
                if (input[0] == '\\')
                {
                    escaping = true;
                }
                else
                {
                    output.Append(input[0]);
                }
                input = input[1..];
            }
            
            throw new FormatException("Unterminated quoted string");
        }
        
        var tokens = new List<string>();
        while(line.Length > 0)
        {
            if (char.IsWhiteSpace(line[0]))
            {
                line = line[1..];
            }
            else
            {
                tokens.Add(ReadWord(ref line, TokenType.Word));
            }
        }

        return tokens;
    }
}

public record struct Token(TokenType Type, string Value);

public enum TokenType
{
    Word,
}