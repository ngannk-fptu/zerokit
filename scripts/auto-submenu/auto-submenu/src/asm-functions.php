<?php

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

class ASM_Functions_Free
{
	function asm_replace_dates($post, $string)
	{
		if (!isset($post) || !isset($string) || empty($string)) {
			return "";
		}

		$format_pattern = "([a-zA-Z\s\\\\:\/,]*)";

		// PHP 5.3 and upwards compatible, use preg_replace_callback for regular expressions with /e parameter instead of preg_replace
		// http://wordpress.org/support/topic/php-55-preg_replace-e-modifier-depricated?replies=1
		$post_date_gmt = $post->post_date_gmt;
		$string = preg_replace("/\%post_date_gmt\(\)/", mysql2date('F jS, Y', $post_date_gmt), $string);
		$callback =
			function ($matches) use ($post_date_gmt) {
				return mysql2date($matches[1], $post_date_gmt);
			};
		$string = preg_replace_callback("/\%post_date_gmt\(" . $format_pattern . "\)/", $callback, $string);
		$string = str_replace("%post_date_gmt", $post_date_gmt, $string);

		$post_date = $post->post_date;
		$string = preg_replace("/\%post_date\(\)/", mysql2date('F jS, Y', $post_date), $string);
		$callback =
			function ($matches) use ($post_date) {
				return mysql2date($matches[1], $post_date);
			};
		$string = preg_replace_callback("/\%post_date\(" . $format_pattern . "\)/", $callback, $string);
		$string = str_replace("%post_date", $post_date, $string);

		return $string;
	}
	function asm_replace_placeholders($post, $string)
	{
		$string = wp_strip_all_tags($string, true);

		$userdata = get_userdata($post->post_author);
		$string = str_replace("%post_author", $userdata ? $userdata->data->display_name : '', $string);
		$string = str_replace("%post_title", $post->post_title, $string);

		$string = $this->asm_replace_dates($post, $string);

		// Remove remaining %post_ occurrences.
		$pattern = "/" . "((\((?P<lbrack>(\S*))))?" . "\%post_[-\w]*(?P<brackets>(\(((?P<inner>[^\(\)]*)|(?P>brackets))\)))" . "(((?P<rbrack>(\S*))\)))?" . "/";
		$string = preg_replace($pattern, '', $string);

		$pattern = "/%post_[-\w]*(?P<brackets>(\(((?P<inner>[^\(\)]*)|(?P>brackets))\)))?/";
		$string = preg_replace($pattern, '', $string);

		$pattern = "/%post_[-\w]*(\([-\w]*\))?/";
		$string = preg_replace($pattern, '', $string);

		return $string;
	}

	function asm_get_page_children($page_id)
	{
		$query_arr = array();

		$query_arr = array(
			'post_parent' => $page_id,
			'post_type' => 'page',
			'post_status' => 'publish'
		);

		$query_arr['order'] = "ASC";
		$query_arr['orderby'] = "menu_order";
		$query_arr['numberposts'] = -1; // default value of -1 returns all posts
		$query_arr['offset'] = 0;

		return get_children($query_arr);
	}

	function asm_block_editor_add_submenu_child_pages_recursive(&$result_parent, $page_id, $class_name, $asm_item_depth, $asm_item_titles)
	{
		$posts = $this->asm_get_page_children($page_id);

		if (count($posts) == 0) {
			return;
		}

		foreach ((array) $posts as $pkey => $post) {
			$child = array(
				"blockName" => 'core/navigation-link',
				"attrs" => array(
					"type" => "post",
					"kind" => "post-type",
					"id" => $post->ID,
					// Set the label of the new menu item. Replace the placeholders in the title by the properties of the post
					"label" => $this->asm_replace_placeholders($post, $asm_item_titles),
					"url" => $post->guid, // First permalink is stored as guid
					// Skip className attribute for now. (See classic menu implementation for caveats)
					"className" => $class_name
				),
				"innerBlocks" => array()
			);

			if ($asm_item_depth > 0) {
				$this->asm_block_editor_add_submenu_child_pages_recursive($child, $post->ID, $class_name, $asm_item_depth - 1, $asm_item_titles);
			}

			$result_parent["innerBlocks"][] = $child;
		}
		$result_parent["blockName"] = 'core/navigation-submenu';
	}

	function asm_block_editor_add_submenu_child_pages(&$result_parent, &$original_item, $page_id, $asm_item_depth)
	{
		$get_attribute_value = fn($i, $k, $def) => is_array($i) && array_key_exists("attrs", $i) && array_key_exists($k, $i["attrs"]) ? $i["attrs"][$k] : $def;
		$asm_item_titles = $get_attribute_value($original_item, "asm_item_titles", "%post_title");
		$class_name = $get_attribute_value($original_item, "className", '');
		$result_item = array_merge($original_item, array("innerBlocks" => array()));

		$result_parent["innerBlocks"][] = &$result_item;

		$this->asm_block_editor_add_submenu_child_pages_recursive($result_item, $page_id, $class_name, $asm_item_depth - 1, $asm_item_titles);
	}
}

?>