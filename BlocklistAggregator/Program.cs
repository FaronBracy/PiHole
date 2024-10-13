using System.Text.RegularExpressions;

namespace BlocklistAggregator;

public class Program
{
   public static async Task<string> DownloadTextFileAsync( string url )
   {
      using HttpClient client = new HttpClient();
      try
      {
         // Download the text file
         string content = await client.GetStringAsync( url );
         return content;
      }
      catch ( Exception ex )
      {
         // Handle exceptions (e.g., network errors, invalid URL)
         Console.WriteLine( $"An error occurred: {ex.Message}" );
         return string.Empty;
      }
   }

   public static string StripIPs( string content )
   {
      // Use a regular expression to remove IP addresses and leading whitespace
      string pattern = @"^\s*\d{1,3}(\.\d{1,3}){3}\s+";
      string result = Regex.Replace( content, pattern, "", RegexOptions.Multiline );
      return result;
   }

   public static async Task Main( string[] args )
   {
      //string url = "https://v.firebog.net/hosts/Easyprivacy.txt";
      string url = "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt";
      string content = await DownloadTextFileAsync( url );
      string strippedContent = StripIPs( content );
      Console.WriteLine( strippedContent );
   }
}
