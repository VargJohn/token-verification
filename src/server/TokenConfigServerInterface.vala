namespace Tokenverification {
    [DBus (name = "com.zuel.token")]
    public interface TokenConfigServerInterface : Object {
    	public struct UserInfo {
    		public string name {get; set;}
    		public string email {get; set;}
    	}
        public abstract UserInfo get_user_info (int txn_id, string token) throws IOError;
        public signal void token_verify_failed (int txn_id, string name);
    }
}
