using System.Text.RegularExpressions;

namespace BlocklistAggregator;

public class Program
{
   public static async Task Main( string[] args )
   {
      Blocklist blocklist = new Blocklist();

      // Blocklist sources
      // https://github.com/mullvad/dns-blocklists?tab=readme-ov-file#lists
      // https://firebog.net/

      string[] suspiciousLists = new string[]
      {
         "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
         "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
         "https://v.firebog.net/hosts/static/w3kbl.txt"
      };

      string[] advertisingLists = new string[]
      {
         "https://adaway.org/hosts.txt",
         "https://v.firebog.net/hosts/AdguardDNS.txt",
         "https://v.firebog.net/hosts/Admiral.txt",
         "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
         "https://v.firebog.net/hosts/Easylist.txt",
         "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
         "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
         "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
         "https://small.oisd.nl/rpz",
         "https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Hosts-File.txt",
      };

      string[] trackingAndTelemetryLists = new string[]
      {
        "https://v.firebog.net/hosts/Easyprivacy.txt",
        "https://v.firebog.net/hosts/Prigent-Ads.txt",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
        "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.amazon.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.apple.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.huawei.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.winoffice.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.tiktok.extended.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.lgwebos.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.vivo.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.oppo-realme.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.xiaomi.txt"
      };

      string[] maliciousLists = new string[]
      {
         "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
         //"https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
         "https://raw.githubusercontent.com/davidonzo/Threat-Intel/refs/heads/master/lists/latestdomains.txt", // one above no longer working
         "https://v.firebog.net/hosts/Prigent-Crypto.txt",
         "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
         "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
         "https://phishing.army/download/phishing_army_blocklist_extended.txt",
         "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
         "https://v.firebog.net/hosts/RPiList-Malware.txt",
         "https://v.firebog.net/hosts/RPiList-Phishing.txt",
         "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
         "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
         "https://urlhaus.abuse.ch/downloads/hostfile/"
      };

      string[] adultLists = new string[]
      {
         "https://nsfw.oisd.nl/rpz"
      };

      string[] otherLists = new string[]
      {
         "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser",
         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt", // Gambling
         // "https://raw.githubusercontent.com/mullvad/dns-blocklists/refs/heads/main/files/social" // Social Media
      };

      string[] urls = suspiciousLists
         .Concat( advertisingLists )
         .Concat( trackingAndTelemetryLists )
         .Concat( maliciousLists )
         .Concat( adultLists )
         .Concat( otherLists )
         .ToArray();

      foreach ( string url in urls )
      {
         await AddBlocklistFromUrl( url, blocklist );
      }

      blocklist.WriteToFile( "dns-block-aggregate" );
   }

   private static async Task<AddBlockListResult> AddBlocklistFromUrl( string url, Blocklist blocklist )
   {
      Log( $"Downloading {url}" );
      string content = await DownloadTextFileAsync( url );
      Log( "Cleaning up and Removing Duplicates" );
      AddBlockListResult result = blocklist.AddList( content );
      Log( result.ToString() );
      return result;
   }

   public static string Log( string message )
   {
      string logStatement = $"{DateTime.Now:HH:mm:ss.fffffff} - {message}";
      Console.WriteLine( logStatement );
      return logStatement;
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
         if ( CanSkip( line ) )
         {
            continue;
         }

         string cleanedLine = StripIPs( line );
         cleanedLine = ReplaceJunk( cleanedLine );
         cleanedLine = StripAllWhitespace( cleanedLine );

         bool result = _uniqueBlocklist.Add( cleanedLine.ToLowerInvariant() );
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

   public bool CanSkip( string contentLine )
   {
      if ( string.IsNullOrWhiteSpace( contentLine ) )
      {
         return true;
      }

      // Use a regular expression to check for the specified characters
      string pattern = @"[#:;_!@$]";
      return Regex.IsMatch( contentLine, pattern );
   }

   /* Filtering Rules based on junk in files
      null or whitespace - delete entire line
      CNAME . at the end - delete CNAME .
      || at the start - delete ||
      ^ at the end - delete ^
      ::1 localhost - delete entire line
      *. at the start - delete *.
      ; at the start - delete entire line
      any whitespace - delete
      _ in the domain anywhere - delete the entire line
      0.0.0.0 at the start delete 0.0.0.0
   */

   public string StripIPs( string contentLine )
   {
      // Use a regular expression to remove IP addresses and leading whitespace
      string ipPattern = @"^\s*\d{1,3}(\.\d{1,3}){3}\s+";
      string withoutIPs = Regex.Replace( contentLine, ipPattern, "", RegexOptions.Multiline );
      return withoutIPs;
   }

   public string ReplaceJunk( string contentLine )
   {
      contentLine = contentLine.Replace( "CNAME .", string.Empty, StringComparison.OrdinalIgnoreCase );
      contentLine = contentLine.Replace( "*.", string.Empty, StringComparison.OrdinalIgnoreCase );
      contentLine = contentLine.Replace( "||", string.Empty, StringComparison.OrdinalIgnoreCase );
      contentLine = contentLine.Replace( "^", string.Empty, StringComparison.OrdinalIgnoreCase );
      contentLine = contentLine.Replace( "0.0.0.0", string.Empty, StringComparison.OrdinalIgnoreCase );
      return contentLine;
   }

   public string StripAllWhitespace( string contentLine )
   {
      // Use a regular expression to remove all whitespace characters
      string pattern = @"\s+";
      string result = Regex.Replace( contentLine, pattern, string.Empty );
      return result;
   }

   public string WriteToFile( string fileName )
   {
      fileName = $"{fileName}-{DateTime.Now:MM-dd-yyyy}.txt";
      List<string> alphaUniqueList = _uniqueBlocklist.OrderBy( x => x ).ToList();
      File.WriteAllLines( fileName, alphaUniqueList );
      return fileName;
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


/*
09:48:32.1213405 - Downloading https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt
09:48:32.6677083 - Cleaning up and Removing Duplicates
09:48:32.7492788 - ItemsAdded: 43166, DuplicateItems: 2
09:48:32.7496058 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts
09:48:32.8723230 - Cleaning up and Removing Duplicates
09:48:32.8726319 - ItemsAdded: 57, DuplicateItems: 0
09:48:32.8727154 - Downloading https://v.firebog.net/hosts/static/w3kbl.txt
09:48:33.0135855 - Cleaning up and Removing Duplicates
09:48:33.0143293 - ItemsAdded: 351, DuplicateItems: 5
09:48:33.0144630 - Downloading https://adaway.org/hosts.txt
09:48:33.4159567 - Cleaning up and Removing Duplicates
09:48:33.4404358 - ItemsAdded: 6486, DuplicateItems: 55
09:48:33.4406193 - Downloading https://v.firebog.net/hosts/AdguardDNS.txt
09:48:33.7217979 - Cleaning up and Removing Duplicates
09:48:33.9871116 - ItemsAdded: 174810, DuplicateItems: 1053
09:48:33.9872610 - Downloading https://v.firebog.net/hosts/Admiral.txt
09:48:34.0916733 - Cleaning up and Removing Duplicates
09:48:34.0945321 - ItemsAdded: 98, DuplicateItems: 1544
09:48:34.0946525 - Downloading https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt
09:48:34.4367727 - Cleaning up and Removing Duplicates
09:48:34.4863845 - ItemsAdded: 39678, DuplicateItems: 2838
09:48:34.4865404 - Downloading https://v.firebog.net/hosts/Easylist.txt
09:48:34.6838680 - Cleaning up and Removing Duplicates
09:48:34.7114870 - ItemsAdded: 68, DuplicateItems: 44126
09:48:34.7116238 - Downloading https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext
09:48:35.7090596 - Cleaning up and Removing Duplicates
09:48:35.7129828 - ItemsAdded: 1748, DuplicateItems: 1794
09:48:35.7131051 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts
09:48:35.8414758 - Cleaning up and Removing Duplicates
09:48:35.8416581 - ItemsAdded: 8, DuplicateItems: 1
09:48:35.8417449 - Downloading https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts
09:48:36.1720364 - Cleaning up and Removing Duplicates
09:48:36.2000449 - ItemsAdded: 8593, DuplicateItems: 9808
09:48:36.2002278 - Downloading https://small.oisd.nl/rpz
09:48:37.6568780 - Cleaning up and Removing Duplicates
09:48:37.7852326 - ItemsAdded: 3794, DuplicateItems: 117735
09:48:37.7853521 - Downloading https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Hosts-File.txt
09:48:37.9234995 - Cleaning up and Removing Duplicates
09:48:37.9248852 - ItemsAdded: 168, DuplicateItems: 987
09:48:37.9249680 - Downloading https://v.firebog.net/hosts/Easyprivacy.txt
09:48:38.1419730 - Cleaning up and Removing Duplicates
09:48:38.1755129 - ItemsAdded: 14018, DuplicateItems: 28983
09:48:38.1756702 - Downloading https://v.firebog.net/hosts/Prigent-Ads.txt
09:48:38.3119342 - Cleaning up and Removing Duplicates
09:48:38.3150932 - ItemsAdded: 1645, DuplicateItems: 2625
09:48:38.3151862 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts
09:48:38.7233696 - Cleaning up and Removing Duplicates
09:48:38.7259680 - ItemsAdded: 1447, DuplicateItems: 583
09:48:38.7261460 - Downloading https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
09:48:38.8276617 - Cleaning up and Removing Duplicates
09:48:38.8281621 - ItemsAdded: 271, DuplicateItems: 76
09:48:38.8282186 - Downloading https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
09:48:39.7796253 - Cleaning up and Removing Duplicates
09:48:39.7929369 - ItemsAdded: 12281, DuplicateItems: 2473
09:48:39.7930722 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.amazon.txt
09:48:39.9418713 - Cleaning up and Removing Duplicates
09:48:39.9424982 - ItemsAdded: 258, DuplicateItems: 112
09:48:39.9426165 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.apple.txt
09:48:40.0801408 - Cleaning up and Removing Duplicates
09:48:40.0803783 - ItemsAdded: 81, DuplicateItems: 28
09:48:40.0804503 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.huawei.txt
09:48:40.1992798 - Cleaning up and Removing Duplicates
09:48:40.1995322 - ItemsAdded: 122, DuplicateItems: 14
09:48:40.1995944 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.winoffice.txt
09:48:40.3345935 - Cleaning up and Removing Duplicates
09:48:40.3350539 - ItemsAdded: 314, DuplicateItems: 75
09:48:40.3351298 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.tiktok.extended.txt
09:48:40.4772353 - Cleaning up and Removing Duplicates
09:48:40.4780602 - ItemsAdded: 513, DuplicateItems: 100
09:48:40.4781360 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.lgwebos.txt
09:48:40.6075797 - Cleaning up and Removing Duplicates
09:48:40.6080427 - ItemsAdded: 337, DuplicateItems: 5
09:48:40.6081136 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.vivo.txt
09:48:40.7484053 - Cleaning up and Removing Duplicates
09:48:40.7487287 - ItemsAdded: 204, DuplicateItems: 26
09:48:40.7487893 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.oppo-realme.txt
09:48:40.9092207 - Cleaning up and Removing Duplicates
09:48:40.9097751 - ItemsAdded: 471, DuplicateItems: 14
09:48:40.9098529 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.xiaomi.txt
09:48:41.0520967 - Cleaning up and Removing Duplicates
09:48:41.0526436 - ItemsAdded: 277, DuplicateItems: 70
09:48:41.0527180 - Downloading https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt
09:48:41.4404823 - Cleaning up and Removing Duplicates
09:48:41.4510843 - ItemsAdded: 11625, DuplicateItems: 738
09:48:41.4511719 - Downloading https://raw.githubusercontent.com/davidonzo/Threat-Intel/refs/heads/master/lists/latestdomains.txt
09:48:41.5902977 - Cleaning up and Removing Duplicates
09:48:41.5905704 - ItemsAdded: 133, DuplicateItems: 0
09:48:41.5906193 - Downloading https://v.firebog.net/hosts/Prigent-Crypto.txt
09:48:41.7489466 - Cleaning up and Removing Duplicates
09:48:41.7593748 - ItemsAdded: 11325, DuplicateItems: 166
09:48:41.7595046 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts
09:48:41.9074239 - Cleaning up and Removing Duplicates
09:48:41.9096701 - ItemsAdded: 2069, DuplicateItems: 120
09:48:41.9097405 - Downloading https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt
09:48:42.0774042 - Cleaning up and Removing Duplicates
09:48:42.0791797 - ItemsAdded: 2046, DuplicateItems: 0
09:48:42.0793730 - Downloading https://phishing.army/download/phishing_army_blocklist_extended.txt
09:48:42.3953541 - Cleaning up and Removing Duplicates
09:48:42.5064862 - ItemsAdded: 138369, DuplicateItems: 18385
09:48:42.5066105 - Downloading https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt
09:48:42.7091885 - Cleaning up and Removing Duplicates
09:48:42.7093218 - ItemsAdded: 0, DuplicateItems: 0
09:48:42.7093613 - Downloading https://v.firebog.net/hosts/RPiList-Malware.txt
09:48:43.1280564 - Cleaning up and Removing Duplicates
09:48:43.6000107 - ItemsAdded: 387895, DuplicateItems: 40822
09:48:43.6001113 - Downloading https://v.firebog.net/hosts/RPiList-Phishing.txt
09:48:43.8579672 - Cleaning up and Removing Duplicates
09:48:43.9991968 - ItemsAdded: 3588, DuplicateItems: 155496
09:48:43.9993022 - Downloading https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt
09:48:44.1532063 - Cleaning up and Removing Duplicates
09:48:44.1583774 - ItemsAdded: 8103, DuplicateItems: 37
09:48:44.1584565 - Downloading https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts
09:48:44.2972977 - Cleaning up and Removing Duplicates
09:48:44.2981578 - ItemsAdded: 874, DuplicateItems: 51
09:48:44.2982169 - Downloading https://urlhaus.abuse.ch/downloads/hostfile/
09:48:44.5665660 - Cleaning up and Removing Duplicates
09:48:44.5671463 - ItemsAdded: 73, DuplicateItems: 312
09:48:44.5672028 - Downloading https://nsfw.oisd.nl/rpz
09:48:47.1070615 - Cleaning up and Removing Duplicates
09:48:48.1578065 - ItemsAdded: 490071, DuplicateItems: 491820
09:48:48.1579181 - Downloading https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser
An error occurred: Response status code does not indicate success: 403 (Forbidden).
09:48:48.7227238 - Cleaning up and Removing Duplicates
09:48:48.7228090 - ItemsAdded: 0, DuplicateItems: 0
09:48:48.7228687 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt
09:48:49.0924279 - Cleaning up and Removing Duplicates
09:48:49.3837868 - ItemsAdded: 412567, DuplicateItems: 610
 */