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
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.amazon.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.apple.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.huawei.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.winoffice.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.tiktok.extended.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.lgwebos.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.vivo.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.oppo-realme.txt",
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.xiaomi.txt"
      };

      string[] maliciousLists = new string[]
      {
         "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
         "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
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
07:51:20.1981320 - Downloading https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt
   07:51:20.6550992 - Cleaning up and Removing Duplicates
   07:51:20.8410680 - ItemsAdded: 82796, DuplicateItems: 4
   07:51:20.8413621 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts
   07:51:20.9388892 - Cleaning up and Removing Duplicates
   07:51:20.9391933 - ItemsAdded: 57, DuplicateItems: 0
   07:51:20.9392603 - Downloading https://v.firebog.net/hosts/static/w3kbl.txt
   07:51:21.1022960 - Cleaning up and Removing Duplicates
   07:51:21.1028526 - ItemsAdded: 350, DuplicateItems: 5
   07:51:21.1029119 - Downloading https://adaway.org/hosts.txt
   07:51:21.4004532 - Cleaning up and Removing Duplicates
   07:51:21.4111443 - ItemsAdded: 6486, DuplicateItems: 55
   07:51:21.4112431 - Downloading https://v.firebog.net/hosts/AdguardDNS.txt
   07:51:21.5681592 - Cleaning up and Removing Duplicates
   07:51:21.6488732 - ItemsAdded: 56575, DuplicateItems: 1034
   07:51:21.6489874 - Downloading https://v.firebog.net/hosts/Admiral.txt
   07:51:21.7480863 - Cleaning up and Removing Duplicates
   07:51:21.7490356 - ItemsAdded: 866, DuplicateItems: 24
   07:51:21.7490840 - Downloading https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt
   07:51:22.0241805 - Cleaning up and Removing Duplicates
   07:51:22.0825549 - ItemsAdded: 39623, DuplicateItems: 2898
   07:51:22.0826650 - Downloading https://v.firebog.net/hosts/Easylist.txt
   07:51:22.2163151 - Cleaning up and Removing Duplicates
   07:51:22.2328686 - ItemsAdded: 336, DuplicateItems: 29658
   07:51:22.2329785 - Downloading https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext
   07:51:22.7733860 - Cleaning up and Removing Duplicates
   07:51:22.7766222 - ItemsAdded: 1971, DuplicateItems: 1566
   07:51:22.7766757 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts
   07:51:22.8682230 - Cleaning up and Removing Duplicates
   07:51:22.8683448 - ItemsAdded: 8, DuplicateItems: 1
   07:51:22.8683935 - Downloading https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts
   07:51:23.0261786 - Cleaning up and Removing Duplicates
   07:51:23.0633437 - ItemsAdded: 10329, DuplicateItems: 10531
   07:51:23.0634942 - Downloading https://small.oisd.nl/rpz
   07:51:24.2781759 - Cleaning up and Removing Duplicates
   07:51:24.3594395 - ItemsAdded: 8073, DuplicateItems: 83042
   07:51:24.3595511 - Downloading https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Hosts-File.txt
   07:51:24.4551300 - Cleaning up and Removing Duplicates
   07:51:24.4563309 - ItemsAdded: 150, DuplicateItems: 944
   07:51:24.4563853 - Downloading https://v.firebog.net/hosts/Easyprivacy.txt
   07:51:24.6234544 - Cleaning up and Removing Duplicates
   07:51:24.6436170 - ItemsAdded: 36736, DuplicateItems: 2634
   07:51:24.6437073 - Downloading https://v.firebog.net/hosts/Prigent-Ads.txt
   07:51:24.7503983 - Cleaning up and Removing Duplicates
   07:51:24.7529901 - ItemsAdded: 1066, DuplicateItems: 2668
   07:51:24.7530859 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts
   07:51:24.8736222 - Cleaning up and Removing Duplicates
   07:51:24.8757677 - ItemsAdded: 1462, DuplicateItems: 568
   07:51:24.8758508 - Downloading https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
   07:51:24.9851429 - Cleaning up and Removing Duplicates
   07:51:24.9856075 - ItemsAdded: 271, DuplicateItems: 76
   07:51:24.9856541 - Downloading https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
   07:51:26.0373811 - Cleaning up and Removing Duplicates
   07:51:26.0482035 - ItemsAdded: 12950, DuplicateItems: 1239
   07:51:26.0482901 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.amazon.txt
   07:51:26.1658522 - Cleaning up and Removing Duplicates
   07:51:26.1664052 - ItemsAdded: 466, DuplicateItems: 108
   07:51:26.1664704 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.apple.txt
   07:51:26.2526730 - Cleaning up and Removing Duplicates
   07:51:26.2530273 - ItemsAdded: 308, DuplicateItems: 21
   07:51:26.2530716 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.huawei.txt
   07:51:26.3387120 - Cleaning up and Removing Duplicates
   07:51:26.3388914 - ItemsAdded: 84, DuplicateItems: 13
   07:51:26.3389368 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.winoffice.txt
   07:51:26.4270396 - Cleaning up and Removing Duplicates
   07:51:26.4276948 - ItemsAdded: 581, DuplicateItems: 117
   07:51:26.4277427 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.tiktok.extended.txt
   07:51:26.5135036 - Cleaning up and Removing Duplicates
   07:51:26.5139701 - ItemsAdded: 406, DuplicateItems: 43
   07:51:26.5140174 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.lgwebos.txt
   07:51:26.6090866 - Cleaning up and Removing Duplicates
   07:51:26.6098530 - ItemsAdded: 1085, DuplicateItems: 36
   07:51:26.6098951 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.vivo.txt
   07:51:26.6989044 - Cleaning up and Removing Duplicates
   07:51:26.6990777 - ItemsAdded: 75, DuplicateItems: 16
   07:51:26.6991336 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.oppo-realme.txt
   07:51:26.7868154 - Cleaning up and Removing Duplicates
   07:51:26.7872111 - ItemsAdded: 333, DuplicateItems: 61
   07:51:26.7872602 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.xiaomi.txt
   07:51:26.8768011 - Cleaning up and Removing Duplicates
   07:51:26.8772720 - ItemsAdded: 381, DuplicateItems: 104
   07:51:26.8773195 - Downloading https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt
   07:51:27.0551532 - Cleaning up and Removing Duplicates
   07:51:27.0928303 - ItemsAdded: 20130, DuplicateItems: 5669
   07:51:27.0931824 - Downloading https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt
   07:51:27.5035780 - Cleaning up and Removing Duplicates
   07:51:27.5037870 - ItemsAdded: 133, DuplicateItems: 0
   07:51:27.5038300 - Downloading https://v.firebog.net/hosts/Prigent-Crypto.txt
   07:51:27.6187891 - Cleaning up and Removing Duplicates
   07:51:27.6284671 - ItemsAdded: 11296, DuplicateItems: 4986
   07:51:27.6285506 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts
   07:51:27.7234989 - Cleaning up and Removing Duplicates
   07:51:27.7255227 - ItemsAdded: 2052, DuplicateItems: 137
   07:51:27.7255767 - Downloading https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt
   07:51:27.9340720 - Cleaning up and Removing Duplicates
   07:51:27.9354922 - ItemsAdded: 2046, DuplicateItems: 0
   07:51:27.9355389 - Downloading https://phishing.army/download/phishing_army_blocklist_extended.txt
   07:51:28.1896247 - Cleaning up and Removing Duplicates
   07:51:28.3456205 - ItemsAdded: 218300, DuplicateItems: 38215
   07:51:28.3460022 - Downloading https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt
   07:51:28.4933003 - Cleaning up and Removing Duplicates
   07:51:28.4934181 - ItemsAdded: 0, DuplicateItems: 0
   07:51:28.4934594 - Downloading https://v.firebog.net/hosts/RPiList-Malware.txt
   07:51:28.8529334 - Cleaning up and Removing Duplicates
   07:51:29.2942574 - ItemsAdded: 393136, DuplicateItems: 38802
   07:51:29.2946303 - Downloading https://v.firebog.net/hosts/RPiList-Phishing.txt
   07:51:29.5780140 - Cleaning up and Removing Duplicates
   07:51:29.9507994 - ItemsAdded: 165582, DuplicateItems: 254935
   07:51:29.9511870 - Downloading https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt
   07:51:30.0717945 - Cleaning up and Removing Duplicates
   07:51:30.0769011 - ItemsAdded: 8080, DuplicateItems: 61
   07:51:30.0769565 - Downloading https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts
   07:51:30.1666292 - Cleaning up and Removing Duplicates
   07:51:30.1674179 - ItemsAdded: 910, DuplicateItems: 3
   07:51:30.1674595 - Downloading https://urlhaus.abuse.ch/downloads/hostfile/
   07:51:30.3301040 - Cleaning up and Removing Duplicates
   07:51:30.3305227 - ItemsAdded: 80, DuplicateItems: 160
   07:51:30.3305653 - Downloading https://nsfw.oisd.nl/rpz
   07:51:32.4048104 - Cleaning up and Removing Duplicates
   07:51:33.3245801 - ItemsAdded: 479965, DuplicateItems: 483312
   07:51:33.3246824 - Downloading https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser
   07:51:33.6914651 - Cleaning up and Removing Duplicates
   07:51:33.6948811 - ItemsAdded: 2396, DuplicateItems: 1160
   07:51:33.6949264 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt
   07:51:33.9921525 - Cleaning up and Removing Duplicates
   07:51:34.2897150 - ItemsAdded: 490954, DuplicateItems: 915
 */