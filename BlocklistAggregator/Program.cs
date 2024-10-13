using System.Text.RegularExpressions;

namespace BlocklistAggregator;

public class Program
{
   public static async Task Main( string[] args )
   {
      Blocklist blocklist = new Blocklist();

      string url = "https://v.firebog.net/hosts/Easyprivacy.txt";
      Console.WriteLine( $"{PrecisionTime()} - Downloading {url}" );
      string content = await DownloadTextFileAsync( url );
      Console.WriteLine( $"{PrecisionTime()} - Stripping Content" );
      string strippedContent = StripIPsAndComments( content );
      Console.WriteLine( $"{PrecisionTime()} - Removing Duplicates" );
      AddBlockListResult result = blocklist.AddList( strippedContent );
      Console.WriteLine( $"{PrecisionTime()} - {result}" );

      url = "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt";
      Console.WriteLine( $"{PrecisionTime()} - Downloading {url}" );
      content = await DownloadTextFileAsync( url );
      Console.WriteLine( $"{PrecisionTime()} - Stripping Content" );
      strippedContent = StripIPsAndComments( content );
      Console.WriteLine( $"{PrecisionTime()} - Removing Duplicates" );
      blocklist.AddList( strippedContent );
      Console.WriteLine( $"{PrecisionTime()} - {result}" );
   }

   public static string PrecisionTime()
   {
      return $"{DateTime.Now:HH:mm:ss.fffffff}";
   }

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

   public static string StripIPsAndComments( string content )
   {
      // Use a regular expression to remove IP addresses and leading whitespace
      string ipPattern = @"^\s*\d{1,3}(\.\d{1,3}){3}\s+";
      string withoutIPs = Regex.Replace( content, ipPattern, "", RegexOptions.Multiline );

      // Use a regular expression to remove lines starting with #
      string commentPattern = @"^\s*#.*(\r?\n|$)";
      string result = Regex.Replace( withoutIPs, commentPattern, "", RegexOptions.Multiline );

      return result;
   }
}

public class Blocklist
{
   private readonly HashSet<string> _uniqueBlocklist = new HashSet<string>();

   public AddBlockListResult AddList( string content )
   {
      int itemsAdded = 0;
      int duplicateItems = 0;

      string[] lines = content.Split( '\n' );
      foreach ( string line in lines )
      {
         if ( string.IsNullOrWhiteSpace( line ) )
         {
            continue;
         }

         bool result = _uniqueBlocklist.Add( line.Trim() );
         if ( result )
         {
            itemsAdded++;
         }
         else
         {
            duplicateItems++;
         }
      }

      return new AddBlockListResult
      {
         ItemsAdded = itemsAdded,
         DuplicateItems = duplicateItems
      };
   }
}

public class AddBlockListResult
{
   public int ItemsAdded { get; set; }
   public int DuplicateItems { get; set; }

   public override string ToString()
   {
      return $"{nameof( ItemsAdded )}: {ItemsAdded}, {nameof( DuplicateItems )}: {DuplicateItems}";
   }
}
