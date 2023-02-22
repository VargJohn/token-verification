/* application.vala
 *
 * Copyright 2023 varghese
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

namespace Tokenverification {
    public class TokenApplication : Gtk.Application, Initable {
        private TokenConfigServerInterface token_config_server_interface;
        private int txn_id;
        private TokenJsAdapter key_cloak_adapter;
        private TokenWindow token_window;

        public TokenApplication (string[] args) throws Error {
            Object (application_id: "com.zuel.vjohn.TokenVerification", flags: ApplicationFlags.FLAGS_NONE);
            Gtk.init(ref args);
            init ();
            txn_id = 0;
            token_window = null;
        }

        construct {
            ActionEntry[] action_entries = {
                { "about", this.on_about_action },
                { "preferences", this.on_preferences_action },
                { "quit", this.quit }
            };
            this.add_action_entries (action_entries, this);
            this.set_accels_for_action ("app.quit", { "<primary>q" });
        }

        public bool init (Cancellable? cancellable = null) {
            try {
                token_config_server_interface =
                    Bus.get_proxy_sync (BusType.SESSION, "com.zuel.token",
                                                         "/com/zuel/token");

                /* Connecting to signal get_user_info_reply */
                token_config_server_interface.token_verify_failed.connect ((id, name) => {
                    stdout.printf ("Received certificate check failed notification: Txn Id %d with userinfo '%s'\n", id, name);
                    //key_cloak_adapter.token_js_adapter_renew_token();
                });
            } catch (Error e) {
                stderr.printf ("%s\n", e.message);
            }
            key_cloak_adapter = new TokenJsAdapter();
            return true;
        }

        public override void activate () {
            base.activate ();
			key_cloak_adapter.token_js_adapter_get_authorization_code();
        }

        public void execute () {
            keycloak_user_info_loop();
            return;
        }


        public async bool soup_get_authorization_code (string code) {
            string url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=926307265015-etns6om67olbt3tlg6kpgid5qrh26ibl.apps.googleusercontent.com&redirect_uri=urn:ietf:wg:oauth:2.0:oob&scope=https://www.googleapis.com/auth/userinfo.profile&response_type=code";
            Soup.Session session = new Soup.Session ();
            Soup.Message msg = new Soup.Message ("GET", url);
            session.send_message (msg);

            if (msg.status_code == 200) {
                stdout.write (msg.response_body.data);
                code = (string) msg.response_body.flatten ().data;
                return true;
            } else {
                stdout.printf ("Request failed with status code: %u\n", msg.status_code);
            }

            return (false);
        }

        public async bool soup_get_token (string token) {
            string url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=926307265015-etns6om67olbt3tlg6kpgid5qrh26ibl.apps.googleusercontent.com&redirect_uri=urn:ietf:wg:oauth:2.0:oob&scope=https://www.googleapis.com/auth/userinfo.profile&response_type=code";
            Soup.Session session = new Soup.Session ();
            Soup.Message msg = new Soup.Message ("GET", url);
            session.send_message (msg);

            if (msg.status_code == 200) {
                stdout.write (msg.response_body.data);
                token = (string) msg.response_body.flatten().data;;
                return true;
            } else {
                stdout.printf ("Request failed with status code: %u\n", msg.status_code);
            }

            return (false);
        }


        public async void keycloak_user_info_loop (Cancellable? cancellable = null) {
             stdout.printf ("Keycloak User Info loop started.\n");
             while (cancellable == null || (!cancellable.is_cancelled())){
                 try {
                    TokenConfigServerInterface.UserInfo user_info = {"unknown", "unknown"};

                    if (key_cloak_adapter.authentication_done){
                        stdout.printf("Try to retreive User Info...\n");
                        user_info =
                                token_config_server_interface.get_user_info (this.txn_id++,
                                                                             key_cloak_adapter.token);
                            stdout.printf ("Received User Information: Txn Id %d with userinfo: Name: '%s email: %s'\n",
                                            txn_id-1, user_info.name, user_info.email);
                            if(user_info.name == "unknown") {
								key_cloak_adapter.token_js_adapter_renew_token();
                            }


                            display_user_info(ref user_info);
                     }
                     yield this.wait_async(10000, cancellable);
                 }catch (IOError.CANCELLED e) {
                     debug("stopped getting authenticated.");
                     break;
                 }catch (Error e) {
                     debug("Error in authenticate loop: %s", e.message);
                     break;
                 }
             }

         }

        public  void display_user_info (ref TokenConfigServerInterface.UserInfo user_info) {
            if (token_window == null) {
                token_window = new Tokenverification.TokenWindow (this);
            }
            // Show the user information in dialog
			token_window.set_user_label("Name:" + user_info.name + "  Email:" + user_info.email);
            token_window.present ();
        }

        private void on_about_action () {
            string[] authors = { "varghese" };
            Gtk.show_about_dialog (this.active_window,
                                   "program-name", "tokenverification",
                                   "logo-icon-name", "com.zuel.vjohn.TokenVerification",
                                   "authors", authors,
                                   "version", "0.1.0",
                                   "copyright", "© 2023 varghese");
        }

        private void on_preferences_action () {
            message ("app.preferences action activated");
        }

        private async void wait_async(uint interval, Cancellable? cancellable =    null) throws IOError.CANCELLED {
            var timeout = new TimeoutSource(interval);
            var canc_src = new CancellableSource(cancellable);
            source_set_dummy_callback(canc_src);
            timeout.add_child_source(canc_src);
            timeout.set_callback(() => {
             wait_async.callback();
             return false;
            });
            timeout.attach();
            yield;
        }

    }
}
