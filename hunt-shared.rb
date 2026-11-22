require 'json'
require 'ipaddr'
require 'set'

module SharedHunts
  OOB = %w[oast.fun oast.pro oast.live oast.site oast.online oast.me interact.sh oastify.com burpcollaborator.net dnslog.cn ceye.io requestrepo.com].freeze
  MODELS = %w[api.deepseek.com dashscope.aliyuncs.com dashscope-intl.aliyuncs.com dashscope-us.aliyuncs.com open.bigmodel.cn api.z.ai api.moonshot.cn api.moonshot.ai api.kimi.com code.kimi.com api.kimi.ai api.minimax.io api.minimax.cn api.minimaxi.com ark.cn-beijing.volces.com api.siliconflow.cn api.siliconflow.com api.stepfun.com api.stepfun.ai tokenhub.tencentmaas.com api.lkeap.cloud.tencent.com api.hunyuan.cloud.tencent.com qianfan.baidubce.com api.xiaomimimo.com api-inference.modelscope.cn openrouter.ai api.novita.ai zenmux.ai api.ofox.ai api.together.xyz api.groq.com api.tensorx.ai api.openai.com api.anthropic.com generativelanguage.googleapis.com api.mistral.ai api.x.ai].freeze
  BACKUP = %r{/\.(?:git/(?:HEAD|config)|hg/|svn/)|/\.env(?:\.(?:bak|old|backup|local))?$|backup\.(?:zip|tar|sql)|db_back|(?:database|dump)\.sql|wp-config\.php\.(?:bak|old|save)|web\.config\.(?:old|bak)}i
  SENSITIVE = %r{/(?:login|signin|admin|wp-admin|wp-login|api/auth|user/login|account|checkout|upload)}i
  PROBE = %r{(?:union(?:\s|\+|%20)+select|sleep\(|extractvalue|\.\./|%2e%2e|/etc/passwd|<script|%3cscript|\$\{|\{\{|/\.git/|/\.env|wp-config|phpinfo)}i
  READER = %r{Claude-User \(claude-code/|\A(?:QwenCode|KimiCLI|opencode)/}
  TOOL = %r{\A(?:curl|python-requests|Python-urllib)/|sqlmap|nuclei|Fuzz Faster U Fool|Nikto|dirsearch|WPScan|katana|dalfox|HeadlessChrome}i

  def self.scan(kind, rows, local, servers, allowed)
    backups = Hash.new { |table, key| table[key] = Set.new }
    readers = Hash.new { |table, key| table[key] = [[],[]] }
    spread = {}
    emitted = Set.new
    report = lambda do |hunt, source, target, bucket|
      key = [hunt, source, target, bucket]
      yield({hunt: hunt, source: source, target: target, window: bucket}) if emitted.add?(key)
    end
    rows.each do |rec|
      source, dest = rec.values_at('id.orig_h','id.resp_h')
      next unless source && dest
      stamp = rec.fetch('ts').to_i
      hour = stamp / 3600 * 3600
      case kind
      when 'dns','ssl'
        next unless servers.any? { |net| net.include?(source) }
        name = rec[kind=='dns' ? 'query' : 'server_name'].to_s.downcase.chomp('.')
        if kind=='dns' && OOB.any? { |zone| name.end_with?(".#{zone}") }
          report.call('callback_service_query',source,name,hour)
        elsif kind=='ssl' && allowed.none? { |net| net.include?(source) } && MODELS.any? { |zone| name==zone || name.end_with?(".#{zone}") }
          report.call('model_service_sni',source,name,hour)
        end
      when 'conn'
        if rec['proto']=='tcp' && [8530,8531].include?(rec['id.resp_p']) && rec['history'].to_s.include?('ShA') && local.none? { |net| net.include?(source) } && servers.any? { |net| net.include?(dest) }
          report.call('external_wsus_port',source,dest,hour)
        end
      when 'http'
        host = (rec['host'] || dest).downcase
        path = rec['uri'].to_s.split('?',2).first.to_s
        agent = rec['user_agent'].to_s
        report.call('reader_client_identifier',source,host,hour) if READER.match?(agent)
        report.call('ffuf_client_identifier',source,host,hour) if agent.include?('Fuzz Faster U Fool v2.1.0-dev')
        if READER.match?(agent) || TOOL.match?(agent) || PROBE.match?(rec['uri'].to_s)
          times = readers[[source,host]]
          times[READER.match?(agent) ? 0 : 1] << stamp
        end
        next if local.any? { |net| net.include?(source) } || servers.none? { |net| net.include?(dest) }
        if BACKUP.match?(path)
          report.call('backup_path_success_status',source,host,hour) if [200,206].include?(rec['status_code'])
          backups[[source,hour]].add(path)
          report.call('backup_path_sweep',source,nil,hour) if backups[[source,hour]].size >= 5
        end
        report.call('wsus_admin_uri',source,host,hour) if %r{/(?:ApiRemoting30/WebService|ServerSyncWebService/ServerSyncWebService|ReportingWebService/ReportingWebService)\.asmx}i.match?(path)
        if SENSITIVE.match?(path) || PROBE.match?(rec['uri'].to_s)
          key = [host, stamp / 2400 * 2400]
          state = spread[key] ||= [Set.new,0]
          state[0].add(source)
          state[1] += 1
        end
      end
    end
    readers.each do |(source,host),(reads,tools)|
      sorted = tools.sort
      stamp = reads.find do |read|
        near = sorted.bsearch { |tool| tool >= read-7200 }
        near && near <= read+7200
      end
      report.call('reader_and_tool',source,host,stamp / 3600 * 3600) if stamp
    end
    spread.each do |(host,bucket),(sources,count)|
      report.call('distributed_web_probing',nil,host,bucket) if sources.size >= 50 && count <= 10*sources.size
    end
  end
end

if $PROGRAM_NAME == __FILE__
  kind = ARGV.shift
  abort 'Usage: LOCAL_NETS=cidrs ruby hunt-shared.rb http|dns|ssl|conn [Zeek JSON logs...]' unless %w[http dns ssl conn].include?(kind)
  nets = lambda { |value| value.split(',').map { |net| IPAddr.new(net) } }
  local = nets.call(ENV.fetch('LOCAL_NETS'))
  servers = nets.call(ENV.fetch('SERVER_NETS',ENV.fetch('LOCAL_NETS')))
  allowed = nets.call(ENV.fetch('ALLOWED_AI_NETS',''))
  SharedHunts.scan(kind, ARGF.each_line.lazy.reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) }, local, servers, allowed) { |hit| puts JSON.generate(hit) }
end