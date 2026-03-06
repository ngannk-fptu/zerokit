<?php
/*
 * Plugin Name: Auto Submenu - Free
 * Plugin URI: https://wordpress.telodelic.nl/auto-submenu
 * Description: Dynamic menus: Add a page to your menu and then let WordPress automatically add the child pages.
 * Version: 1.0.5
 * Author: Diana van de Laarschot
 * Author URI: https://wordpress.telodelic.nl
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 5.4
 * Tested up to: 6.9
 * Requires PHP: 7.4
 * Text Domain: auto-submenu
 */

/*  Copyright 2024 Diana van de Laarschot (email : mail@telodelic.nl)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License, version 2, as 
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

require('src/asm-functions.php');

class ASM_Manager_Free
{
	const OPTION_NAME = 'asm_options';
	const VERSION = '1.0.0';
	const CSS_VERSION = '1.0.0';
	const JS_VERSION = '1.0.0';

	protected $options = null;
	protected $defaults = array('version' => self::VERSION);

	/**
	 * Constructor
	 */
	function __construct()
	{
		// For use in Appearance > Menus and Theme > Customize:
		add_filter('gettext', array(&$this, 'asm_gettext'), 10, 3);
		add_action('publish_page', array(&$this, 'asm_publish_page')); // Checkbox: Automatically add new top-level and all its child pages to this menu (Auto Submenu)

		// For use via Block Editor:
		add_action('enqueue_block_editor_assets', array(&$this, 'asm_enqueue_block_editor_assets_js'));
		add_action('block_core_navigation_render_inner_blocks', array(&$this, 'asm_block_core_navigation_render_inner_blocks'));

		// Add button to plugin description
		add_filter('plugin_row_meta', array(&$this, 'asm_plugin_row_meta'), 10, 2);

		// Auto-update if a new plugin version is available via central wordpress.org repository
		add_filter('auto_update_plugin', array(&$this, 'asm_auto_update_plugin'), 10, 2);
	} // function

	function ASM_Manager_Free()
	{
		$this->get_options();
		$this->__construct();
	} // function

	function asm_block_core_navigation_render_inner_blocks_recursive(&$result_parent, &$original_parent, &$original_item, &$taxonomies)
	{
		// We need to work on the inner array. (Array methods will throw if it's a WP_Block)
		if (is_a($original_item, 'WP_Block')) {
			$original_item = $original_item->parsed_block;
		}
		$result_item = array_merge($original_item, array("innerBlocks" => array()));
		if (array_key_exists("attrs", $original_item)) {
			$get_attribute_value = fn($i, $k, $def) => is_array($i) && array_key_exists("attrs", $i) && array_key_exists($k, $i["attrs"]) ? $i["attrs"][$k] : $def;
			// Augment page object with a list of its posts: Append posts to $result
			if ($get_attribute_value($original_item, "asm_unfold", false)) {
				$id = $get_attribute_value($original_item, "id", null);
				$asm_item_depth = $get_attribute_value($original_item, "asm_item_depth", 10);
				$asm_item_depth = ($asm_item_depth <= 0 || $asm_item_depth >= 3) ? 3 : $asm_item_depth;

				// Add child pages as submenu under page
			 	(new ASM_Functions_Free())->asm_block_editor_add_submenu_child_pages($result_parent, $original_item, $id, $asm_item_depth);
			} else {
				// Append to correct parent
				$original_parent["innerBlocks"][] = &$result_item;
			}

			if (is_array($original_item["innerBlocks"])) {
				foreach ($original_item["innerBlocks"] as $key => &$innerBlock) {
					$this->asm_block_core_navigation_render_inner_blocks_recursive($result_item, $original_item, $innerBlock, $taxonomies);
				}
			}
		}
	}

	// Workaround. Dropdown carets are not generated for parent items
	// Reported here: https://core.trac.wordpress.org/ticket/60572#ticket
	function decorate_block_recursive(&$menu_item)
	{
		$menu_item = new WP_Block($menu_item, array("showSubmenuIcon" => 1)); // This is the actual fix, 'activate' the context attribute to make WordPress honor it.

		if (count($menu_item->parsed_block["innerBlocks"]) > 0) {
			foreach ($menu_item->parsed_block["innerBlocks"] as $key => &$innerBlock) {
				$this->decorate_block_recursive($innerBlock);
			}
		}
	}

	function asm_block_core_navigation_render_inner_blocks($items)
	{
		$this->get_options();

		$result = array("innerBlocks" => array());

		$taxonomies = get_taxonomies(array('show_in_nav_menus' => true), 'objects');
		foreach ($items as $key => $item) {
			$this->asm_block_core_navigation_render_inner_blocks_recursive($result, $result, $item->parsed_block, $taxonomies);
		}

		// Workaround. Dropdown carets are not generated for parent items
		// Reported here: https://core.trac.wordpress.org/ticket/60572#ticket
		foreach ($result["innerBlocks"] as $key => &$innerBlock) {
			$this->decorate_block_recursive($innerBlock);
		}

		return new WP_Block_List($result["innerBlocks"]);
	}

	function asm_auto_update_plugin($update, $item)
	{
		return($item->slug == 'auto-submenu') ? true : $update;
	} // function

	private function get_options()
	{
		// already did the checks
		if (isset($this->options)) {
			return $this->options;
		}

		// first call, get the options
		$options = get_option(self::OPTION_NAME);

		// options exist
		if ($options !== false) {
			$new_version = version_compare($options['version'], self::VERSION, '<');
			$desync = array_diff_key($this->defaults, $options) !== array_diff_key($options, $this->defaults);

			// update options if version changed, or we have missing/extra (out of sync) option entries 
			if ($new_version || $desync) {
				$new_options = array();

				// check for new options and set defaults if necessary
				foreach ($this->defaults as $option => $value) {
					$new_options[$option] = isset($options[$option]) ? $options[$option] : $value;
				}

				// update version info
				$new_options['version'] = self::VERSION;

				update_option(self::OPTION_NAME, $new_options);
				$this->options = $new_options;
			} else // no update required
			{
				$this->options = $options;
			}
		} else // either new install or version from before versioning existed 
		{
			update_option(self::OPTION_NAME, $this->defaults);
			$this->options = $this->defaults;
		}

		return $this->options;
	}

	static function asm_uninstall()
	{
		// We're uninstalling, so delete all custom fields on nav_menu_items that the ASM plugin added
		// Unless the premium version is active
		$installed_plugins = get_plugins();
		if (!(array_key_exists('auto-submenu-premium', $installed_plugins) || in_array('auto-submenu-premium', $installed_plugins, true))) {
			// Premium version not installed, safe to delete all fields
			delete_metadata('nav_menu_item', null, '_asm-unfold', '', true);
			delete_metadata('nav_menu_item', null, '_asm-orderby', '', true);
			delete_metadata('nav_menu_item', null, '_asm-order', '', true);
			delete_metadata('nav_menu_item', null, '_asm-item-depth', '', true);
			delete_metadata('nav_menu_item', null, '_asm-item-titles', '', true);
		}
	} // function

	/* 
	 * Add JS for ASM fields site-editor.php (Appearance > Editor, the block editor)
	 */
	function asm_enqueue_block_editor_assets_js( /* no $hook parameter in this case */)
	{
		wp_enqueue_script(
			'asm_enqueue_block_editor_assets_core_navigation_link_js',
			plugins_url('src/blocks/asm_core_navigation_link/build/index.js', __FILE__),
			['wp-blocks'],
			self::JS_VERSION,
			true
		);
	} // function

	function asm_gettext($translated, $original, $textdomain)
	{
		// Some users expect to see a checkbox for this option.
		// Change the text of the checkbox, clearly showing that the plugin is active and the functionality behaves differently now.
		// https://wordpress.org/support/topic/no-automatically-add-new-child-pages-option-in-menus-when-plugin-activated/
		if ('Automatically add new top-level pages to this menu' == $translated) {
			$translated = 'When publishing a top-level page, automatically add it to this menu. When publishing a child page, add it if the parent is in the menu (Auto Submenu)';
		}

		return $translated;
	}

	/**
	 * When publishing a top-level page or child page, automatically add it to this menu (Auto Submenu)
	 */
	function asm_publish_page($post_id)
	{
		// Theme supports custom menus?
		if (!current_theme_supports('menus')) {
			return;
		}

		// Published page has parent?
		$post = get_post( $post_id );
		if ( ! $post->post_parent ) {
			return;
		}

		// Get menus with auto_add enabled
		$auto_add = get_option('nav_menu_options');
		if (empty($auto_add) || !is_array($auto_add) || !isset($auto_add['auto_add'])) {
			return;
		}
		$auto_add = $auto_add['auto_add'];
		if (empty($auto_add) || !is_array($auto_add)) {
			return;
		}

		// Loop through the menus to find page parent
		foreach ($auto_add as $menu_id) {
			$menu_items = wp_get_nav_menu_items($menu_id, array('post_status' => 'publish,draft'));
			if (!is_array($menu_items)) {
				continue;
			}

			// Assumption of current implementation: Top level pages are added to the menu only once.
			$menu_child = NULL;
			$menu_parent = NULL;

			// Find the child menu item and the parent menu item for this child page
			foreach ($menu_items as $menu_item) {
				if ($menu_item->object_id == $post->ID) {
					$menu_child = $menu_item;
				}
				if ($menu_item->object_id == $post->post_parent) {
					$menu_parent = $menu_item;
				}
			}

			// Parent not in menu, abort.
			if ( !$menu_parent ){
				break;
			}

			if ( $menu_child ) {
				// Is child menu item already under correct parent? (If so, do nothing)
				if ( $menu_child->menu_item_parent != $menu_parent->ID ) {
					// Update the existing child menu item, move to correct parent
					wp_update_nav_menu_item( $menu_id, $menu_child->db_id, array(
						'menu-item-position' => $post->menu_order,
						'menu-item-object-id' => $post->ID,
						'menu-item-object' => $post->post_type,
						'menu-item-parent-id' => $menu_parent->ID,
						'menu-item-type' => 'post_type',
						'menu-item-status' => 'publish'
					) );
				}
			} else {
				// No menu item yet. Add new menu item for child page
				wp_update_nav_menu_item( $menu_id, 0, array(
					'menu-item-position' => $post->menu_order,
					'menu-item-object-id' => $post->ID,
					'menu-item-object' => $post->post_type,
					'menu-item-parent-id' => $menu_parent->ID,
					'menu-item-type' => 'post_type',
					'menu-item-status' => 'publish'
				) );
			}
		}
	}

	/*
	 * Add a button to the plugin description on the plugins page
	 */
	function asm_plugin_row_meta($links, $file)
	{
		if (plugin_basename(__FILE__) == $file) {
			$row_meta = array(
				'docs' => '<a href="' . esc_url('https://wordpress.telodelic.nl/auto-submenu/') . '" target="_blank" aria-label="' . esc_attr__('Go Premium', 'auto-submenu') . '" style="color:green;">' . esc_html__('Go Premium', 'auto-submenu') . '</a>'
			);
			return array_merge($links, $row_meta);
		}

		return $links;
	}
}

$asm_manager_free = new ASM_Manager_Free();

// Register the uninstall hook. Should be done after the class has been defined.
register_uninstall_hook(__FILE__, array('ASM_Manager_Free', 'asm_uninstall'));

?>