package main

import(
  "fmt"
  "flag"
  "os"
  "bufio"
  "errors"
  "text/tabwriter"
  "github.com/miekg/dns"
  "strings"
)

type result struct {
  IPAddress string
  Hostname string
}

type empty struct{}


func lookupA(fqdn, serverAddr string)([]string, error) {
  var m dns.Msg
  var ips []string
  m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
  in, err := dns.Exchange(&m, serverAddr)
  if err != nil {
    return ips, err
  }
  if len(in.Answer) < 1 {
    return ips, errors.New("no answer")
  }

  for _, answer := range in.Answer {
    if a, ok := answer.(*dns.A); ok {
      ips = append(ips, a.A.String()) 
    }
  }
  return ips, nil
}

func lookupCNAME(fqdn, serverAddr string)([]string, error) {
  var m dns.Msg
  var fqdns []string
  m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
  in, err := dns.Exchange(&m, serverAddr)
  if err != nil {
    return fqdns, err
  }
  if len(in.Answer) < 1 {
    return fqdns, errors.New("no answer")
  }

  for _, answer := range in.Answer {
    if c, ok := answer.(*dns.CNAME); ok {
      fqdns = append(fqdns, c.Target)
    }
  }
  return fqdns, nil
}


func lookup(fqdn, serverAddr string) []result {
  //fmt.Println(serverAddr)
  var results []result
  var cfqdn = fqdn // Don't modify the original
  for {
    cnames, err := lookupCNAME(cfqdn, serverAddr)
    if err == nil && len(cnames) > 0 {
      cfqdn = cnames[0]
      continue // We have to process the next CNAME
    }
    ips, err := lookupA(cfqdn, serverAddr)
    if err != nil {
      break // There are no A records for this hostname
    }
    for _, ip := range ips {
      results = append(results, result{IPAddress: ip, Hostname: fqdn})
    }
    break // We have processed all the results
  }
  return results
}


func worker(tracker chan empty, fqdns chan string, gather chan[]result, serverAddr string) {
  for fqdn := range fqdns {
    results := lookup(fqdn, serverAddr)
    if len(results) > 0 {
      gather <- results
    }
  }
  var e empty
  tracker <- e
}



func main() {

  var (
    flDomain      = flag.String("domain", "", "The domain to perform guessing against.")
    flWordlist    = flag.String("wordlist", "", "The wordlist to use for guessing.")
    flWorkerCount = flag.Int("c", 100, "The amount of workers to use.")
    flResolvers = flag.String("resolver", "8.8.8.8,1.1.1.1,8.8.4.4,9.9.9.9,149.112.112.112,208.67.222.222,1.0.0.1,76.76.19.19,76.223.122.150", "The resolvers to use.")
  )
  flag.Parse()

  if *flDomain == "" || *flWordlist == "" {
    fmt.Println("-domain and -wordlist are required")
    fmt.Println("Example: ./subbruter -domain example.com -wordlist subdomains.txt -c 1000 -resolver 8.8.8.8,1.1.1.1")
    os.Exit(1)
  }
  //fmt.Println(*flWorkerCount, *flServerAddr)


  var flServerAddrs = strings.Split(*flResolvers, ",")
  for i, _ := range flServerAddrs {
    flServerAddrs[i] = flServerAddrs[i] + ":53" 
  }

  //var flServerAddrs = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53", "9.9.9.9:53", "149.112.112.112:53", "208.67.222.222:53", "1.0.0.1:53", "76.76.19.19:53", "76.223.122.150:53" }
  var results []result
  fqdns := make(chan string, *flWorkerCount)
  gather := make(chan []result)
  tracker := make(chan empty)

  fh, err := os.Open(*flWordlist)
  if err != nil {
    panic(err)
  }
  defer fh.Close()
  scanner := bufio.NewScanner(fh)

  for i := 0; i < *flWorkerCount; i++ {
    var flServerAddr = flServerAddrs[i % len(flServerAddrs)]
    go worker(tracker, fqdns, gather, flServerAddr)
  }

  for scanner.Scan() {
    fqdns <- fmt.Sprintf("%s.%s", scanner.Text(), *flDomain)
  }

  go func() {
    for r := range gather {
      results = append(results, r...)
    }
    var e empty
    tracker <- e
  }()
  close(fqdns)
  for i := 0; i < *flWorkerCount; i++ {
    <-tracker
  }
  close(gather)
  <-tracker

  w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
  for _, r := range results {
    fmt.Fprintf(w, "%s\t%s\n", r.Hostname, r.IPAddress)
  }
  w.Flush()
}
