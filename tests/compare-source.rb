require 'json'
require 'set'
require 'tmpdir'

pin = '354e8a309803730b8f01fba1489aa0ea00d38ae6'
source = File.expand_path(ARGV.fetch(0))
root = File.expand_path('..', __dir__)
def pinned(source, pin, name)
  text = IO.popen(['git', '-C', source, 'show', "#{pin}:frameworks/artex/#{name}"], &:read)
  abort "Missing pinned #{name}" unless $?.success?
  text
end
def pairs(text)
  text.lines.reject { |line| line.start_with?('#') || line.strip.empty? }.map { |line| line.split("\t").first(2) }.sort
end
abort 'Intel membership mismatch' unless pairs(pinned(source, pin, 'zeek/intel/artex.intel')) == pairs(File.read(File.join(root, 'campaign.intel')))
baseline = %w[artex.rules artex-ip.rules].map { |name| pinned(source, pin, "suricata/#{name}") }.join("\n")
local = Dir[File.join(root, 'campaign*.rules')].sort.map { |path| File.read(path) }.join("\n")
mapping = {}
baseline.lines.grep(/^alert /).each do |line|
  sid = line[/sid:(\d+)/, 1].to_i
  mapping[sid] = case sid
                 when 9726001..9726008 then 1004810
                 when 9726020..9726021 then 1004811
                 when 9726022..9726026 then 1004812 + sid - 9726022
                 when 9726040..9726041 then 1004817
                 when 9726042 then 1004818
                 when 9726060..9726068 then 1004819 + sid - 9726060
                 when 9726514, 9726515, 9726534, 9726535 then 1004832 + sid % 2
                 when 9726500..9726537 then 1004830 + sid % 2
                 else abort "Unmapped baseline SID #{sid}"
                 end
end
Dir.mktmpdir do |work|
  outputs = [baseline, local].map.with_index do |rules, index|
    dir = File.join(work, index.to_s)
    Dir.mkdir(dir)
    path = File.join(dir, 'test.rules')
    File.write(path, rules)
    abort 'Engine replay failed' unless system('suricata', '-r', File.join(root, 'tests/campaign.pcap'), '-S', path, '-l', dir, '--set', 'vars.address-groups.HOME_NET=[10.0.0.0/8]')
    File.foreach(File.join(dir, 'eve.json')).map { |line| JSON.parse(line) }.select { |event| event['event_type'] == 'alert' }.map do |event|
      [event.dig('alert', 'signature_id'), *event.values_at('src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'tx_id')]
    end.to_set
  end
  upstream, candidate = outputs
  abort 'Fixture did not exercise every baseline SID' unless upstream.map(&:first).uniq.sort == mapping.keys.sort
  missing = upstream.reject { |sid, *flow| candidate.include?([mapping.fetch(sid), *flow]) }
  abort "Missing local equivalents: #{missing.inspect}" unless missing.empty?
end
puts "PASS: #{mapping.size} upstream SIDs exercised and mapped by transaction; exact typed intel inventory matches."