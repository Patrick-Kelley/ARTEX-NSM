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
abort "Unexpected HTTP hunts: #{hits}" unless hits.sort == expected.sort
puts 'PASS: HTTP hunt windows, source/host keys and threshold controls'