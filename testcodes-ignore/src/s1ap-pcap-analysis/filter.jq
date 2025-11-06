map(
  (._source.layers) as $L
  |
  ($L.sctp // {}) as $s
  |
  (
    $s["sctp.chunk"]
    | if type=="array" then .[0] else . end
  ) as $c
  |
  {
    ip: {
      src: ($L["ip"]?["ip.src"]  // $L["ipv6"]?["ipv6.src"]),
      dst: ($L["ip"]?["ip.dst"]  // $L["ipv6"]?["ipv6.dst"])
    },
    sctp: {
      chunk_type:   ($c?["sctp.chunk_type"]   // $s?["sctp.chunk_type"]),
      chunk_length: ($c?["sctp.chunk_length"] // $s?["sctp.chunk_length"]),
      tsn:          ($c?["sctp.data_tsn_raw"] // $c?["sctp.data_tsn"] // $s?["sctp.data_tsn_raw"]),
      ssn:          ($c?["sctp.data_ssn"]     // $s?["sctp.data_ssn"])
    },
    s1ap: $L["s1ap"]
  }
)
