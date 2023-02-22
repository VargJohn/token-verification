/* window.vala
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
    [GtkTemplate (ui = "/gui/TokenWindow.ui")]
    public class TokenWindow : Gtk.ApplicationWindow {
        [GtkChild]
        private unowned Gtk.Label label;
        public Gtk.Button button;

        public TokenWindow (Gtk.Application app) {
            Object (application: app);
            button = new Gtk.Button.with_label ("Name:Unknown    Email:Unknown");
    		button.clicked.connect (() => {
        		button.label = "Please wait; Loading";
    		});
    		this.add (button);
    		show_all();
        }

        construct {
            title = "Token Verification: User Details";
            show_all();
		}

		public void set_user_label(string details) {
			button.set_label(details);
			show_all();
		}
    }
}
