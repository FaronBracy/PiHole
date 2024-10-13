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
         "https://raw.githubusercontent.com/mullvad/dns-blocklists/refs/heads/main/files/social" // Social Media
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
   19:04:38.0716899 - Downloading https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt
   19:04:38.5387350 - Stripping Content
   19:04:38.5778129 - Removing Duplicates
   19:04:38.5918622 - ItemsAdded: 79005, DuplicateItems: 0
   19:04:38.5920774 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts
   19:04:38.7146019 - Stripping Content
   19:04:38.7153695 - Removing Duplicates
   19:04:38.7154437 - ItemsAdded: 57, DuplicateItems: 0
   19:04:38.7154851 - Downloading https://v.firebog.net/hosts/static/w3kbl.txt
   19:04:38.8309756 - Stripping Content
   19:04:38.8311716 - Removing Duplicates
   19:04:38.8313149 - ItemsAdded: 350, DuplicateItems: 5
   19:04:38.8313615 - Downloading https://adaway.org/hosts.txt
   19:04:39.4033330 - Stripping Content
   19:04:39.4062595 - Removing Duplicates
   19:04:39.4146468 - ItemsAdded: 6487, DuplicateItems: 55
   19:04:39.4147565 - Downloading https://v.firebog.net/hosts/AdguardDNS.txt
   19:04:39.7560111 - Stripping Content
   19:04:39.7662279 - Removing Duplicates
   19:04:39.7756442 - ItemsAdded: 62113, DuplicateItems: 1035
   19:04:39.7757459 - Downloading https://v.firebog.net/hosts/Admiral.txt
   19:04:39.8869041 - Stripping Content
   19:04:39.8872082 - Removing Duplicates
   19:04:39.8875088 - ItemsAdded: 912, DuplicateItems: 25
   19:04:39.8875516 - Downloading https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt
   19:04:40.0937808 - Stripping Content
   19:04:40.1075320 - Removing Duplicates
   19:04:40.1150384 - ItemsAdded: 39637, DuplicateItems: 2899
   19:04:40.1153612 - Downloading https://v.firebog.net/hosts/Easylist.txt
   19:04:40.2686790 - Stripping Content
   19:04:40.2737602 - Removing Duplicates
   19:04:40.2787434 - ItemsAdded: 326, DuplicateItems: 35808
   19:04:40.2788250 - Downloading https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext
   19:04:40.8291054 - Stripping Content
   19:04:40.8320983 - Removing Duplicates
   19:04:40.8333092 - ItemsAdded: 1974, DuplicateItems: 1574
   19:04:40.8333629 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts
   19:04:40.9985668 - Stripping Content
   19:04:40.9986865 - Removing Duplicates
   19:04:40.9987362 - ItemsAdded: 8, DuplicateItems: 1
   19:04:40.9987731 - Downloading https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts
   19:04:41.1561948 - Stripping Content
   19:04:41.1620022 - Removing Duplicates
   19:04:41.1732408 - ItemsAdded: 9951, DuplicateItems: 10633
   19:04:41.1733978 - Downloading https://small.oisd.nl/rpz
   19:04:42.3957515 - Stripping Content
   19:04:42.4053014 - Removing Duplicates
   19:04:42.4177604 - ItemsAdded: 92500, DuplicateItems: 0
   19:04:42.4178849 - Downloading https://raw.githubusercontent.com/lassekongo83/Frellwits-filter-lists/master/Frellwits-Swedish-Hosts-File.txt
   19:04:42.5064559 - Stripping Content
   19:04:42.5069084 - Removing Duplicates
   19:04:42.5073526 - ItemsAdded: 155, DuplicateItems: 934
   19:04:42.5073941 - Downloading https://v.firebog.net/hosts/Easyprivacy.txt
   19:04:42.6642245 - Stripping Content
   19:04:42.6684552 - Removing Duplicates
   19:04:42.6891629 - ItemsAdded: 36806, DuplicateItems: 2526
   19:04:42.6892810 - Downloading https://v.firebog.net/hosts/Prigent-Ads.txt
   19:04:42.7952543 - Stripping Content
   19:04:42.7958325 - Removing Duplicates
   19:04:42.7968103 - ItemsAdded: 1110, DuplicateItems: 2624
   19:04:42.7968541 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts
   19:04:42.9539997 - Stripping Content
   19:04:42.9546152 - Removing Duplicates
   19:04:42.9551832 - ItemsAdded: 1462, DuplicateItems: 568
   19:04:42.9552187 - Downloading https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
   19:04:43.1048476 - Stripping Content
   19:04:43.1050502 - Removing Duplicates
   19:04:43.1051847 - ItemsAdded: 271, DuplicateItems: 76
   19:04:43.1052211 - Downloading https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
   19:04:44.1832843 - Stripping Content
   19:04:44.1867068 - Removing Duplicates
   19:04:44.1893984 - ItemsAdded: 12941, DuplicateItems: 1235
   19:04:44.1894497 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.amazon.txt
   19:04:44.4402360 - Stripping Content
   19:04:44.4404460 - Removing Duplicates
   19:04:44.4406340 - ItemsAdded: 483, DuplicateItems: 107
   19:04:44.4406651 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.apple.txt
   19:04:44.5738269 - Stripping Content
   19:04:44.5740044 - Removing Duplicates
   19:04:44.5741527 - ItemsAdded: 301, DuplicateItems: 21
   19:04:44.5742107 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.huawei.txt
   19:04:44.6791683 - Stripping Content
   19:04:44.6792754 - Removing Duplicates
   19:04:44.6793598 - ItemsAdded: 80, DuplicateItems: 13
   19:04:44.6793979 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.winoffice.txt
   19:04:44.7814099 - Stripping Content
   19:04:44.7816005 - Removing Duplicates
   19:04:44.7818275 - ItemsAdded: 575, DuplicateItems: 116
   19:04:44.7818608 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.tiktok.extended.txt
   19:04:44.8819020 - Stripping Content
   19:04:44.8820344 - Removing Duplicates
   19:04:44.8821949 - ItemsAdded: 401, DuplicateItems: 42
   19:04:44.8822354 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.lgwebos.txt
   19:04:44.9761940 - Stripping Content
   19:04:44.9763789 - Removing Duplicates
   19:04:44.9766531 - ItemsAdded: 1084, DuplicateItems: 35
   19:04:44.9766922 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.vivo.txt
   19:04:45.0753558 - Stripping Content
   19:04:45.0754599 - Removing Duplicates
   19:04:45.0755192 - ItemsAdded: 74, DuplicateItems: 16
   19:04:45.0755653 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.oppo-realme.txt
   19:04:45.1729676 - Stripping Content
   19:04:45.1731417 - Removing Duplicates
   19:04:45.1732827 - ItemsAdded: 310, DuplicateItems: 61
   19:04:45.1733207 - Downloading https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.xiaomi.txt
   19:04:45.2907964 - Stripping Content
   19:04:45.2909531 - Removing Duplicates
   19:04:45.2911352 - ItemsAdded: 383, DuplicateItems: 105
   19:04:45.2911683 - Downloading https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt
   19:04:45.4581788 - Stripping Content
   19:04:45.4665891 - Removing Duplicates
   19:04:45.4779399 - ItemsAdded: 19250, DuplicateItems: 6017
   19:04:45.4780145 - Downloading https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt
   19:04:45.8927608 - Stripping Content
   19:04:45.8928943 - Removing Duplicates
   19:04:45.8929556 - ItemsAdded: 85, DuplicateItems: 0
   19:04:45.8929953 - Downloading https://v.firebog.net/hosts/Prigent-Crypto.txt
   19:04:46.0191535 - Stripping Content
   19:04:46.0217385 - Removing Duplicates
   19:04:46.0337972 - ItemsAdded: 16133, DuplicateItems: 149
   19:04:46.0338648 - Downloading https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts
   19:04:46.1634829 - Stripping Content
   19:04:46.1641466 - Removing Duplicates
   19:04:46.1646692 - ItemsAdded: 2057, DuplicateItems: 132
   19:04:46.1647027 - Downloading https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt
   19:04:46.3169352 - Stripping Content
   19:04:46.3173474 - Removing Duplicates
   19:04:46.3178303 - ItemsAdded: 2046, DuplicateItems: 0
   19:04:46.3178621 - Downloading https://phishing.army/download/phishing_army_blocklist_extended.txt
   19:04:46.5641838 - Stripping Content
   19:04:46.5906829 - Removing Duplicates
   19:04:46.6327793 - ItemsAdded: 210308, DuplicateItems: 36492
   19:04:46.6329022 - Downloading https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt
   19:04:46.7655601 - Stripping Content
   19:04:46.7656983 - Removing Duplicates
   19:04:46.7657992 - ItemsAdded: 178, DuplicateItems: 0
   19:04:46.7658346 - Downloading https://v.firebog.net/hosts/RPiList-Malware.txt
   19:04:47.0885172 - Stripping Content
   19:04:47.1375807 - Removing Duplicates
   19:04:47.2614504 - ItemsAdded: 360347, DuplicateItems: 0
   19:04:47.2619144 - Downloading https://v.firebog.net/hosts/RPiList-Phishing.txt
   19:04:47.5562053 - Stripping Content
   19:04:47.6017866 - Removing Duplicates
   19:04:47.7145322 - ItemsAdded: 385710, DuplicateItems: 1628
   19:04:47.7146446 - Downloading https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt
   19:04:47.8429016 - Stripping Content
   19:04:47.8437512 - Removing Duplicates
   19:04:47.8460908 - ItemsAdded: 8086, DuplicateItems: 55
   19:04:47.8461360 - Downloading https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts
   19:04:47.9531050 - Stripping Content
   19:04:47.9533070 - Removing Duplicates
   19:04:47.9536756 - ItemsAdded: 910, DuplicateItems: 3
   19:04:47.9537152 - Downloading https://urlhaus.abuse.ch/downloads/hostfile/
   19:04:48.2535704 - Stripping Content
   19:04:48.2537270 - Removing Duplicates
   19:04:48.2538570 - ItemsAdded: 209, DuplicateItems: 36
   19:04:48.2538861 - Downloading https://nsfw.oisd.nl/rpz
   19:04:50.4298323 - Stripping Content
   19:04:50.5235000 - Removing Duplicates
   19:04:50.8192799 - ItemsAdded: 920050, DuplicateItems: 502
   19:04:50.8193789 - Downloading https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser
   19:04:51.1572645 - Stripping Content
   19:04:51.1582428 - Removing Duplicates
   19:04:51.1594028 - ItemsAdded: 2406, DuplicateItems: 1150
   19:04:51.1594417 - Downloading https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt
   19:04:51.4178563 - Stripping Content
   19:04:51.4579104 - Removing Duplicates
   19:04:51.5885329 - ItemsAdded: 434519, DuplicateItems: 314
   19:04:51.5888972 - Downloading https://raw.githubusercontent.com/mullvad/dns-blocklists/refs/heads/main/files/social
   19:04:51.7813143 - Stripping Content
   19:04:51.7903600 - Removing Duplicates
   19:04:51.8009674 - ItemsAdded: 33495, DuplicateItems: 6271
 */