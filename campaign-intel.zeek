@load policy/frameworks/intel/seen
@load policy/frameworks/files/hash-all-files

redef Intel::read_files += { fmt("%s/campaign.intel", @DIR) };