/*
 * This file is part of cc-oci-runtime.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h> 

#include <glib/gstdio.h>
#include <gio/gunixmounts.h>

#include "mount.h"
#include "common.h"
#include "namespace.h"
#include "pod.h"

/** Mounts that will be ignored.
 *
 * These are standard mounts that will be created within the VM
 * automatically, hence do not need to be mounted before the VM is
 * started.
 */
static struct mntent cc_oci_mounts_to_ignore[] =
{
	{ NULL, (char *)"/proc"           , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev"            , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev/pts"        , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev/shm"        , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev/mqueue"     , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/sys"            , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/sys/fs/cgroup"  , NULL, NULL, -1, -1 }
};

/*!
 * Determine if the specified \ref cc_oci_mount represents a
 * mount that can be ignored.
 *
 * \param m \ref cc_oci_mount.
 *
 * \return \c true if mount can be ignored, else \c false.
 */
private gboolean
cc_oci_mount_ignore (struct cc_oci_mount *m)
{
	struct mntent  *me;
	size_t          i;
	size_t          max = CC_OCI_ARRAY_SIZE (cc_oci_mounts_to_ignore);

	if (! m) {
		return false;
	}

	for (i = 0; i < max; i++) {
		me = &cc_oci_mounts_to_ignore[i];

		if (cc_oci_found_str_mntent_match (me, m, mnt_fsname)) {
			goto ignore;
		}

		if (cc_oci_found_str_mntent_match (me, m, mnt_dir)) {
			goto ignore;
		}

		if (cc_oci_found_str_mntent_match (me, m, mnt_type)) {
			goto ignore;
		}

		/* Adding explicit check for bind-mounts here, we should be left with just
		 * the bind-mounts after ignoring the system mounts.
		 */
		//if ( !(m->flags & MS_BIND)) {
		//	goto ignore;
		//}
	}

	return false;

ignore:
	m->ignore_mount = true;
	return true;
}

/*!
 * Free the specified \ref cc_oci_mount.
 *
 * \param m \ref cc_oci_mount.
 */
void
cc_oci_mount_free (struct cc_oci_mount *m)
{
	g_assert (m);

	g_free_if_set (m->mnt.mnt_fsname);
	g_free_if_set (m->mnt.mnt_dir);
	g_free_if_set (m->mnt.mnt_type);
	g_free_if_set (m->mnt.mnt_opts);
	g_free_if_set (m->directory_created);
	g_free_if_set (m->host_path);
	
	g_free (m);
}

/*!
 * Free all mounts.
 *
 * \param mounts List of \ref cc_oci_mount.
 */
void
cc_oci_mounts_free_all (GSList *mounts)
{
	if (! mounts) {
		return;
	}

	g_slist_free_full (mounts, (GDestroyNotify)cc_oci_mount_free);
}

/*!
 * Mount the resource specified by \p m.
 *
 * \param m \ref cc_oci_mount.
 * \param dry_run If \c true, don't actually call \c mount(2),
 * just log what would be done.
 *
 * \return \c true on success, else \c false.
 */
private gboolean
cc_oci_perform_mount (const struct cc_oci_mount *m, gboolean dry_run)
{
	const char *fmt = "%smount%s %s of type %s "
		"onto %s with options '%s' "
		"and flags 0x%lx%s%s";

	int ret;
	struct stat st;

	if (! m) {
		return false;
	}

	g_debug (fmt, dry_run ? "Not " : "",
			"ing",
			m->mnt.mnt_fsname,
			m->mnt.mnt_type,
			m->dest,
			m->mnt.mnt_opts ? m->mnt.mnt_opts : "",
			m->flags,
			dry_run ? " (dry-run mode)" : "",
			"");

	if (dry_run) {
		return true;
	}

	if (stat (m->mnt.mnt_fsname, &st) < 0) {
		g_critical ("Unable to handle mount file:"
				"getting file status  %s (%s)",
				m->mnt.mnt_fsname, strerror (errno));
		return false;
	}

	if (S_ISREG(st.st_mode)) {
		int fd;
		fd = creat (m->dest, st.st_mode);
		if( fd < 0 ) {
			g_critical ("Unable to handle mount file:"
					"creating file %s (%s)",
					m->dest, strerror (errno));
			return false;
		}
		close(fd);

	}

	ret = mount (m->mnt.mnt_fsname,
			m->dest,
			m->mnt.mnt_type,
			m->flags,
			m->mnt.mnt_opts);
	if (ret) {
		int saved = errno;
		gchar *msg;

		msg = g_strdup_printf (": %s", strerror (saved));

		g_critical (fmt,
				"Failed to ",
				"",
				m->mnt.mnt_fsname,
				m->mnt.mnt_type,
				m->dest,
                m->mnt.mnt_opts ? m->mnt.mnt_opts : "",
				m->flags,
				"",
				msg);
		g_free (msg);
	}

	return ret == 0;
}

/*!
 * Setup mount points.
 *
 * \param config \ref cc_oci_config.
 * \param mounts List of \ref cc_oci_mount.
 * \param volume If \c true the mount point is a container volume.
 *
 * \return \c true on success, else \c false.
 */
static gboolean
cc_handle_mounts(struct cc_oci_config *config, GSList *mounts, gboolean volume)
{
	GSList    *l;
	gboolean   ret;
	struct stat st;
	gchar* dirname_dest = NULL;
	gchar* dirname_parent_dest = NULL;
	gchar* c = NULL;
	gchar* workload_dir;

	if (! config) {
		return false;
	}

	workload_dir = cc_oci_get_workload_dir(config);
	if (! workload_dir) {
		return false;
	}

	for (l = mounts; l && l->data; l = g_slist_next (l)) {
		struct cc_oci_mount *m = (struct cc_oci_mount *)l->data;

		if (cc_oci_mount_ignore (m)) {
			continue;
		}

		if ( !config->pod) {
			if (! volume) {
				// bind mount rootfs 
				g_snprintf (m->dest, sizeof (m->dest),
					"%s/%s",
					workload_dir, m->mnt.mnt_dir);
			} else {
				// bind mount to workload_dir and create fsmap
				uint64_t *bytes = (uint64_t*)get_random_bytes(8);
				if ( !bytes) {
					return false;
				}

				gchar *base_name = g_path_get_basename(m->mnt.mnt_dir);
				m->host_path = g_strdup_printf("%"PRIx64"-%s",
						*bytes,
						base_name);
				
				g_snprintf (m->dest, sizeof (m->dest),
					"%s/%s",
					workload_dir, m->host_path);
				
				g_debug("Mounting bind mount %s for mnt_dir %s", m->dest, m->mnt.mnt_dir);
				g_free(bytes);
				g_free(base_name);
			}
		} else {

			if ((! cc_pod_is_vm(config) || cc_pod_is_pod_sandbox(config)) && volume) {
				g_snprintf (m->dest, sizeof (m->dest),
					    "%s/%s/rootfs/%s", workload_dir, config->optarg_container_id, m->mnt.mnt_dir);
			} else {
				g_snprintf (m->dest, sizeof (m->dest),
					    "%s/%s",
					    workload_dir, m->mnt.mnt_dir);
			}
		}

		if (m->mnt.mnt_fsname[0] == '/') {
			if (stat (m->mnt.mnt_fsname, &st)) {
				g_debug ("ignoring mount, %s does not exist", m->mnt.mnt_fsname);
				continue;
			}
			if (! S_ISDIR(st.st_mode)) {
				dirname_dest = g_path_get_dirname(m->dest);
			}
		}

		if (! dirname_dest) {
			dirname_dest = g_strdup(m->dest);
		}

		dirname_parent_dest = g_strdup(dirname_dest);
		if (dirname_parent_dest && ! g_file_test(dirname_parent_dest, G_FILE_TEST_IS_DIR)) {
			/* looking for first parent directory that must be created to mount dest */
			do {
				c = g_strrstr(dirname_parent_dest, "/");
				if (c) {
					*c = '\0';
				} else {
					/* no more path separators '/' */
					break;
				}
			} while(! g_file_test(dirname_parent_dest, G_FILE_TEST_IS_DIR));

			if (c) {
				/* revert last change */
				*c = '/';
				m->directory_created = dirname_parent_dest;
				dirname_parent_dest = NULL;
			}
		}

		g_free_if_set(dirname_parent_dest);

		ret = g_mkdir_with_parents (dirname_dest, CC_OCI_DIR_MODE);
		if (ret < 0) {
			g_critical ("failed to create mount directory: %s (%s)",
					m->dest, strerror (errno));
			g_free(dirname_dest);
			return false;
		}

		g_free(dirname_dest);
		dirname_dest = NULL;

		if (! cc_oci_perform_mount (m, config->dry_run_mode)) {
			return false;
		}
	}

	return true;
}

/*!
 * Setup required OCI mounts.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_oci_handle_mounts (struct cc_oci_config *config)
{
	if (! config) {
		return false;
	}

	return cc_handle_mounts(config, config->oci.mounts, true);
}

/*!
 * Setup pod rootfs mount points.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_pod_handle_mounts (struct cc_oci_config *config)
{
	if (! (config && config->pod)) {
		return true;
	}

	return cc_handle_mounts(config, config->pod->rootfs_mounts, false);
}

/*!
 * Setup container rootfs mount point.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_handle_rootfs_mount (struct cc_oci_config *config)
{
	if (!config || config->pod) {
		return true;
	}

	return cc_handle_mounts(config, config->rootfs_mount, false);
}
/*!
 * Unmount the mount specified by \p m.
 *
 * \param m \ref cc_oci_mount.
 *
 * \return \c true on success, else \c false.
 */
private gboolean
cc_oci_perform_unmount (const struct cc_oci_mount *m)
{
	if (! m) {
		return false;
	}

	g_debug ("unmounting %s", m->dest);

	return umount (m->dest) == 0;
}

/*!
 * Unmount a list of mounts.
 *
 * \param mounts List of \ref cc_oci_mount.
 *
 * \return \c true on success, else \c false.
 */
static gboolean
cc_handle_unmounts (GSList *mounts)
{
	GSList  *l;

	/* umount files and directories */
	for (l = mounts; l && l->data; l = g_slist_next (l)) {
		struct cc_oci_mount *m = (struct cc_oci_mount *)l->data;

		if (m->ignore_mount) {
			/* was never mounted */
			continue;
		}

		if (! cc_oci_perform_unmount (m)) {
			g_critical("failed to umount %s", m->dest);
			return false;
		}
	}

	/* delete directories created by cc_oci_handle_mounts */
	for (l = mounts; l && l->data; l = g_slist_next (l)) {
		struct cc_oci_mount *m = (struct cc_oci_mount *)l->data;

		if (m->ignore_mount) {
			/* was never mounted */
			continue;
		}

		if (m->directory_created) {
			if (! cc_oci_rm_rf(m->directory_created)) {
				g_critical("failed to delete %s", m->directory_created);
			}
		}
	}

	return true;
}


/*!
 * Unmount all OCI mounts.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_oci_handle_unmounts (const struct cc_oci_config *config)
{
	GSList  *l;
	struct oci_cfg_namespace *ns;
	gboolean mountns = false;

	if (! config) {
		return false;
	}

	/**
	 * At this point qemu is not running if there is
	 * a mount namespace with a path we have join
	 * it and umount all mounted resources
	 */
	for (l = config->oci.oci_linux.namespaces;
			l && l->data;
			l = g_slist_next (l)) {
		ns = (struct oci_cfg_namespace *)l->data;

		if (ns->type == OCI_NS_MOUNT && ns->path) {
			mountns = cc_oci_ns_join (ns);
			break;
		}
	}

	/**
	 * if there is NOT a specific mount namespace return true
	 * since namespace created by unshare in \ref cc_oci_ns_setup
	 * is destroyed when qemu ends
	 */
	if (! mountns && (cc_pod_is_vm(config) && !cc_pod_is_pod_sandbox(config))) {
		//return true;
	}

	return cc_handle_unmounts(config->oci.mounts);
}

/*!
 * Unmount all pod mount points.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_pod_handle_unmounts (const struct cc_oci_config *config)
{
	if (! (config && config->pod)) {
		return true;
	}

	return cc_handle_unmounts(config->pod->rootfs_mounts);
}

/*!
 * Unmount container rootfs mount point.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c true on success, else \c false.
 */
gboolean
cc_oci_handle_rootfs_unmount (const struct cc_oci_config *config)
{
	if (!config || config->pod) {
		return true;
	}

	return cc_handle_unmounts(config->rootfs_mount);
}

/*!
 * Convert a list of mounts to a JSON array.
 *
 * Note that the returned array will be empty unless any of the list of
 * mounts provided in \ref CC_OCI_CONFIG_FILE were actually mounted
 * (many are ignored as they are unecessary in the hypervisor case).
 *
 * \param mounts List of \ref cc_oci_mount.
 *
 * \return \c JsonArray on success, else \c NULL.
 */
static JsonArray *
cc_mounts_to_json (GSList *mounts)
{
	JsonArray *array = NULL;
	JsonObject *mount = NULL;
	GSList *l;

	array  = json_array_new ();

	for (l = mounts; l && l->data; l = g_slist_next (l)) {
		struct cc_oci_mount *m = (struct cc_oci_mount *)l->data;

		if (m->ignore_mount) {
			/* was never mounted */
			continue;
		}
		mount = json_object_new ();

		json_object_set_string_member (mount, "destination",
			m->dest);

		if (m->directory_created) {
			json_object_set_string_member (mount, "directory_created",
				m->directory_created);
		}
		
		json_object_set_string_member (mount, "mnt_dir",
			m->mnt.mnt_dir);

		if (m->host_path) {
			json_object_set_string_member (mount, "host_path",
				m->host_path);
		}

		json_array_add_object_element (array, mount);
	}

	return array;
}

/*!
 * Convert the list of OCI mounts to a JSON array.
 *
 * Note that the returned array will be empty unless any of the list of
 * mounts provided in \ref CC_OCI_CONFIG_FILE were actually mounted
 * (many are ignored as they are unecessary in the hypervisor case).
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c JsonArray on success, else \c NULL.
 */
JsonArray *
cc_oci_mounts_to_json (const struct cc_oci_config *config)
{
	return cc_mounts_to_json(config->oci.mounts);
}

/*!
 * Convert the list of pod mounts to a JSON array.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c JsonArray on success, else \c NULL.
 */
JsonArray *
cc_pod_mounts_to_json (const struct cc_oci_config *config)
{
	if (! (config && config->pod)) {
		return NULL;
	}

	return cc_mounts_to_json(config->pod->rootfs_mounts);
}

/*!
 * Convert container rootfs mount to a JSON array.
 *
 * \param config \ref cc_oci_config.
 *
 * \return \c JsonArray on success, else \c NULL.
 */
JsonArray *
cc_oci_rootfs_mount_to_json (const struct cc_oci_config *config)
{
	if (!config || config->pod) {
		return NULL;
	}

	return cc_mounts_to_json(config->rootfs_mount);
}
int
cc_device_for_path(gchar *path, uint *major, uint *minor)
{
	struct stat buf;

	if (! (path && major && minor)) {
		return -1;
	}

	if (stat(path, &buf) == -1) {
		return -1;
	}

	*major = major(buf.st_dev);
	*minor = minor(buf.st_dev);
	
	return 0;
}

gboolean
cc_is_devicemapper(uint major, uint minor)
{
	int ret;
	gchar *sys_path = NULL;
	struct stat buf;

	sys_path = g_strdup_printf("/sys/dev/block/%d:%d/dm", major, minor);

	ret = stat(sys_path, &buf);
	g_free(sys_path);

	if (ret == -1) {
		return false;
	}

	return true;
}

gchar *
cc_mount_point_for_path(const gchar *path) {
	int ret = -1;
	gchar *mount_point = NULL;
	gchar *parent_dir = NULL;
	struct stat parent_stat, cur_stat;

	if (! path) {
		return NULL;
	}

	if ( *path != '/') {
		g_warning("Absolute path not provided %s", path);
		return NULL;
	}

	if (g_strcmp0(path, "/") == 0 ) {
		return g_strdup(path);
	}

	if (stat(path, &cur_stat) == -1) {
		return NULL;
	}

	mount_point = strdup(path);

	while (g_strcmp0(mount_point, "/") != 0) {
		parent_dir = g_path_get_dirname(mount_point);

		ret = lstat(parent_dir, &parent_stat);
		if ( ret == -1) {
			g_free(parent_dir);
			g_free(mount_point);
			return NULL;
		}

		if (cur_stat.st_dev != parent_stat.st_dev) {
			break;
		}

		g_free(mount_point);
		mount_point = parent_dir;
		cur_stat = parent_stat;
	}

	g_free(parent_dir);
	
	if (g_strcmp0(mount_point, "/") == 0) {
		g_free(mount_point);
		return NULL;
	}

	return mount_point;
}
		
int
cc_get_device_and_fstype(gchar *mount_point, gchar **device_name, gchar **fstype) {
	int ret = -1;
	struct mntent ent = { 0 };
	struct mntent *mntent;
	char buf[BUFSIZ];
	FILE *file = NULL;

	if (! (mount_point && device_name && fstype)) {
		g_debug("Invalid input for proc_mounts_path");
		return ret;
	}

	/* note: glib api "g_unix_mounts_get" for fetching mount info, fails in case of
	 * bind mounts. (https://bugzilla.gnome.org/show_bug.cgi?id=747540).
	 * Use getmntent_r instead.
	 */

	file = setmntent(PROC_MOUNTS_FILE, "r");
	if ( !file) {
		g_critical("Could not open file %s", PROC_MOUNTS_FILE);
		return ret;
	}

	while ((mntent = getmntent_r (file, &ent, buf, sizeof (buf))) != NULL) {
		if (mntent->mnt_fsname) {
			if (g_strcmp0(mntent->mnt_dir, mount_point) == 0) {
				*device_name = g_strdup(mntent->mnt_fsname);
				*fstype = g_strdup(mntent->mnt_type);
				ret = 0;
				break;
			}
		}
	}

	if ( !mntent) {
		g_warning("Could not find device name for mount %s", mount_point);
	}

	endmntent(file);
	return ret;
}

// Legacy naming scheme for virtio block devices
// Reference : https://github.com/torvalds/linux/blob/master/drivers/block/virtio_blk.c#L478
int
virtblk_name_format(char *prefix, int index, char *buf, int buflen)
{
	const int base = 'z' - 'a' + 1;
	char *begin = buf + strlen(prefix);
	char *end = buf + buflen;
	char *p;
	int unit;

	p = end - 1;
	*p = '\0';
	unit = base;
	do {
		if (p == begin) {
			return -EINVAL;
		}

		*--p = (char)('a' + (index % unit));
		index = (index / unit) - 1;
	} while (index >= 0);

	memmove(begin, p, (size_t)(end - p));
	memcpy(buf, prefix, strlen(prefix));

	return 0;
}

gchar *
cc_get_virtio_drive_name(int index)
{
	int DISK_NAME_LEN = 32;

	char disk_name[DISK_NAME_LEN];

	if (virtblk_name_format("vd", index, disk_name, DISK_NAME_LEN) != 0) {
		return NULL;
	}

	return strdup(disk_name);
}
