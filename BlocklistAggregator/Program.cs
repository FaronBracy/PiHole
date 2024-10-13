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

   public static async Task Main( string[] args )
   {
      string url = "https://v.firebog.net/hosts/Easyprivacy.txt";
      string content = await DownloadTextFileAsync( url );
      Console.WriteLine( content );
   }
}