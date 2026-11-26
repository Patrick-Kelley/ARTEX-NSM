require_relative '../hunt-shared'

local = [IPAddr.new('10.0.0.0/8')]
servers = [IPAddr.new('10.1.0.0/16')]
allowed = [IPAddr.new('10.1.0.2')]
sample = {'ts'=>1, 'id.orig_h'=>'192.0.2.1', 'id.resp_h'=>'10.1.0.1', 'host'=>'example.test'}
verify = lambda do |kind, cases, expected|
  hits = []
  SharedHunts.scan(kind,cases.map { |row| sample.merge(row) },local,servers,allowed) { |hit| hits << hit[:hunt] }
  abort "#{kind} mismatch: #{hits}" unless hits.sort == expected.sort
end
verify.call('dns',[{'id.orig_h'=>'10.1.0.1','query'=>'a.oast.pro'}, {'id.orig_h'=>'10.2.0.1','query'=>'a.oast.pro'}, {'id.orig_h'=>'10.1.0.1','query'=>'notoast.pro'}],['callback_service_query'])
verify.call('ssl',[{'id.orig_h'=>'10.1.0.1','server_name'=>'API.OPENAI.COM'}, {'id.orig_h'=>'10.1.0.2','server_name'=>'api.openai.com'}, {'id.orig_h'=>'10.1.0.1','server_name'=>'notapi.openai.com'}],['model_service_sni'])
verify.call('conn',[{'proto'=>'tcp','history'=>'ShADad','id.resp_p'=>8531},{'proto'=>'tcp','history'=>'S','id.resp_p'=>8531,'id.orig_h'=>'192.0.2.2'}],['external_wsus_port'])
web = %w[/.env /.env.old /.env.local /.git/config /dump.sql].map { |path| {'uri'=>path,'status_code'=>404} }
verify.call('http',web.first(4),[])
verify.call('http',web + [{'uri'=>'/.env','status_code'=>206},{'uri'=>'/ApiRemoting30/WebService.asmx'}],%w[backup_path_success_status backup_path_sweep wsus_admin_uri])
read = {'user_agent'=>'QwenCode/1','uri'=>'/'}
tool = {'user_agent'=>'Fuzz Faster U Fool v2.1.0-dev','uri'=>'/'}
verify.call('http',[read,tool.merge('ts'=>7201)],%w[reader_client_identifier ffuf_client_identifier reader_and_tool])
verify.call('http',[read,tool.merge('ts'=>7202)],%w[reader_client_identifier ffuf_client_identifier])
spread = (1..50).map { |number| {'uri'=>'/login','id.orig_h'=>"192.0.2.#{number}"} }
verify.call('http',spread,['distributed_web_probing'])
verify.call('http',spread.first(49),[])
verify.call('http',spread*11,[])
puts 'PASS: shared web, DNS, TLS and flow hunt controls'
{'dns'=>['query','callback_service_query'],'ssl'=>['server_name','webhook_service_sni'],'http'=>['host','webhook_service_http']}.each do |kind,(field,hunt)|
  verify.call(kind,[{'id.orig_h'=>'10.1.0.1',field=>'One.Webhook.Site'}, {'id.orig_h'=>'10.1.0.2',field=>'webhook.site.example.org'}, {'id.orig_h'=>'192.0.2.2',field=>'webhook.site'}],[hunt])
end