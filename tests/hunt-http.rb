require_relative '../hunt-http'

rows = []
def row(source, host, time, agent='fixture', uri='/')
  {'id.orig_h'=>source, 'host'=>host, 'ts'=>time, 'method'=>'GET', 'user_agent'=>agent, 'uri'=>uri}
end
%w[192.0.2.1 192.0.2.2 10.0.0.1].each do |source|
  rows << row(source,'example.test',1,'norma/0.4') << row(source,'example.test',1801,'Go-http-client/1.1') << row(source,'other.test',2500,'curl/7.88.1')
end
rows << row('192.0.2.2','example.test',2,'norma/0.4','/page.css?v=3')
rows << row('192.0.2.3','example.test',1,'norma/0.4') << row('192.0.2.3','example.test',1802,'Go-http-client/1.1')
[480,479].each do |seconds|
  [0,600].each do |start|
    seconds.times { |second| 2.times { rows << row("192.0.2.#{seconds-475}",'paced.test',start+second) } }
  end
end
hits = []
HTTPHunts.run(rows,[IPAddr.new('10.0.0.0/8')]) { |hit| hits << [hit[:source],hit[:hunt]] }
expected = [['192.0.2.1','reader_with_enrichment'],['10.0.0.1','reader_with_enrichment'],['192.0.2.3','reader_only'],['192.0.2.1','toolchain_mix'],['192.0.2.2','toolchain_mix'],['192.0.2.5','paced_requests']]
expected.concat(%w[192.0.2.1 192.0.2.2 10.0.0.1 192.0.2.3].map { |source| [source,'reported_default_client'] })
abort "Unexpected HTTP hunts: #{hits}" unless hits.sort == expected.sort
puts 'PASS: HTTP hunt windows, source/host keys and threshold controls'

cases = []
[[100,50],[99,50],[100,49],[1,100]].each_with_index do |(paths,errors), index|
  100.times do |number|
    cases << row("192.0.2.#{20+index}","host#{number%2}.test",59,'fixture',"/page/#{number%paths}?q=#{number}").merge('status_code'=>number<errors ? 404 : 200)
  end
end
cases << row('192.0.2.21','example.test',60,'fixture','/one-more').merge('status_code'=>404)
hits = []
HTTPHunts.run(cases,[]) { |hit| hits << hit }
abort "Unexpected path/error bursts: #{hits}" unless hits == [{hunt:'distinct_paths_and_client_errors',source:'192.0.2.20',minute:0,distinct_paths_at_least:100,client_errors:50}]

versions = [row('192.0.2.30','example.test',1,'norma/2.7'),row('192.0.2.30','example.test',2,'artex-enrich/3'),row('192.0.2.31','example.test',1,'notnorma/2'),row('192.0.2.32','example.test',1,'norma/')]
hits = []
HTTPHunts.run(versions,[]) { |hit| hits << hit }
abort "Unexpected versioned readers: #{hits}" unless hits == [{hunt:'reported_default_client',source:'192.0.2.30',minute:0,requests:2},{hunt:'reader_with_enrichment',source:'192.0.2.30',host:'example.test'}]