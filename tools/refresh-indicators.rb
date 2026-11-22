require 'csv'

source = File.expand_path(ARGV.fetch(0))
pin = '354e8a309803730b8f01fba1489aa0ea00d38ae6'
table = IO.popen(['git', '-C', source, 'show', "#{pin}:iocs/indicators.csv"], &:read)
abort 'Pinned source unavailable' unless $?.success?
rows = CSV.parse(table, headers: true).select { |row| row['framework'].split.include?('artex') }
root = File.expand_path('..', __dir__)
addresses = rows.select { |row| row['type'] == 'ipv4' }
rules = %w[medium low].each_with_index.flat_map do |confidence, index|
  values = addresses.select { |row| row['confidence'] == confidence }.map { |row| row['value'] }.uniq.sort.join(',')
  [["$HOME_NET any -> [#{values}] any", 'outbound'], ["[#{values}] any -> $HOME_NET any", 'inbound']].each_with_index.map do |(header, direction), offset|
    "alert ip #{header} (msg:\"LOCAL Historical ARTEX-associated IP sighting - #{direction} - #{confidence} confidence\"; sid:#{1004830 + index * 2 + offset}; rev:1;)"
  end
end
types = { 'ipv4' => 'ADDR', 'user_agent' => 'SOFTWARE', 'domain' => 'DOMAIN', 'sha256' => 'FILE_HASH', 'url' => 'URL' }
intel = rows.map do |row|
  type = types[row['type']]
  next unless type
  value = row['value']
  type = 'SUBNET' if type == 'ADDR' && value.include?('/')
  value = value.sub(%r{\Ahttps?://}i, '') if type == 'URL'
  [value, "Intel::#{type}", "ThreatDefence-ARTEX-#{row['confidence']}"].join("\t")
end.compact
File.write(File.join(root, 'campaign-ip.rules'), rules.join("\n") + "\n")
File.write(File.join(root, 'campaign.intel'), (["#fields\tindicator\tindicator_type\tmeta.source"] + intel.uniq.sort).join("\n") + "\n")