require 'json'
require 'ipaddr'
require 'set'

module HTTPHunts
  READER = /\Anorma\/\S+/i
  ENRICH = /\Aartex-enrich\/\S+/i
  CLIENTS = [ READER, /\AGo-http-client\/1\.1\z/, ENRICH, /spa-api-recon/i, /\Asqlmap\/1\.9/, /Fuzz Faster U Fool/, /Nmap Scripting Engine/, /HeadlessChrome/, /\Acurl\/7\.88\.1\z/, /\AWget\/1\.21\.3\z/, /\A(?:python-requests\/|Python-urllib\/3\.12)/ ].freeze
  STATIC = /\.(?:m?js|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|otf|avif|mp4|webm)(?:\?|$)/i

  def self.run(records, local_nets)
    readers = {}
    clients = Hash.new { |table, key| table[key] = Set.new }
    rates = Hash.new { |table, key| table[key] = Hash.new(0) }
    bursts = {}
    records.each do |record|
      source = record['id.orig_h']
      host = (record['host'] || record['id.resp_h']).to_s.downcase
      next unless source && !host.empty? && record['ts'] && record['method']
      stamp = record['ts'].to_f
      agent = record['user_agent'].to_s
      minute = stamp.to_i / 60 * 60
      burst = bursts[[source, minute]] ||= [Set.new, 0, 0]
      path = record['uri'].to_s.split('?', 2).first
      burst[0].add(path) if path && !path.empty? && burst[0].size < 100
      burst[1] += 1 if record['status_code'].to_s.match?(/\A4\d\d\z/)
      burst[2] += 1 if READER.match?(agent) || ENRICH.match?(agent)
      key = [source, host]
      if READER.match?(agent) || ((ENRICH.match?(agent) || agent == 'Go-http-client/1.1') && record['method'] == 'GET')
        state = readers[key] ||= {}
        if READER.match?(agent)
          state[:invalid] = true if record['method'] != 'GET' || record['uri'].to_s.split('?', 2).first.to_s.match?(STATIC)
          state[:reader] = [state[:reader] || stamp, stamp].min
        else
          state[:enrich] = [state[:enrich] || stamp, stamp].min
        end
      end
      family = CLIENTS.index { |pattern| pattern.match?(agent) }
      if family && local_nets.none? { |network| network.include?(source) }
        clients[[source, stamp.to_i / 3600]].add(family)
      end
      rates[[source, host, stamp.to_i / 600]][stamp.to_i] += 1
    end
    bursts.each do |(source, minute), (paths, errors, defaults)|
      yield({hunt: 'reported_default_client', source: source, minute: minute, requests: defaults}) if defaults > 0
      yield({hunt: 'distinct_paths_and_client_errors', source: source, minute: minute, distinct_paths_at_least: 100, client_errors: errors}) if paths.size == 100 && errors >= 50
    end
    readers.each do |(source, host), state|
      next if !state[:reader] || state[:invalid]
      paired = state[:enrich] && (state[:enrich] - state[:reader]).abs <= 1800
      yield({hunt: paired ? 'reader_with_enrichment' : 'reader_only', source: source, host: host})
    end
    clients.each do |(source, hour), families|
      yield({hunt: 'toolchain_mix', source: source, hour: hour * 3600, families: families.size}) if families.size >= 3
    end
    windows = Hash.new { |table, key| table[key] = [] }
    rates.each do |(source, host, epoch), counts|
      next if counts.size < 480
      values = counts.values
      mean = values.sum.to_f / values.size
      deviation = Math.sqrt(values.sum { |value| (value - mean)**2 } / (values.size - 1))
      next unless deviation <= 0.8 && [[1.2,2.1,4],[4.0,5.2,10],[17.0,20.5,40]].any? { |low, high, max| mean.between?(low, high) && values.max <= max }
      windows[[source, host]] << epoch * 600
    end
    windows.each do |(source, host), epochs|
      epochs.sort.each_cons(2) do |first, second|
        next unless second - first < 7 * 86400
        yield({hunt: 'paced_requests', source: source, host: host, windows: [first, second]})
        break
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  networks = ENV.fetch('LOCAL_NETS', '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7').split(',').map { |net| IPAddr.new(net) }
  HTTPHunts.run(ARGF.each_line.lazy.reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) }, networks) { |hit| puts JSON.generate(hit) }
end