package prekeyserver

import "strings"

// Design:
// - a production level storage mechanism that stores data into separate files
// - the storage is very simple:
// - each from will be hashed into a hex-string using sha256
//   if the path is /var/data/otrng-prekey-storage
//   a specific data point will be 1234567ABCDEFADBDCDCDCDCDCDAAAAAA123538892322332ABDCDFFFFACDADDD
// - all information about it will be stored in:
// - /var/data/otrng-prekey-storage/1234/1234567ABCDEFADBDCDCDCDCDCDAAAAAA123538892322332ABDCDFFFFACDADDD
// - inside of this directory will be a .lock file if it's currently used
// - it will have one file for each instance tag, for example:
//   - for instance tag 0x1234AABB, will be directory
//     /var/data/otrng-prekey-storage/1234/1234567ABCDEFADBDCDCDCDCDCDAAAAAA123538892322332ABDCDFFFFACDADDD/1234AABB
//   - inside of this directory will be two files, called cp.bin and pp.bin, containing the binary representation of
//     the client profile and prekey profile, if they exist
//   - there will be a directory called pm, where each pm entry will be of the form /1245AABB.bin, containing the raw
//     binary representation of the identifier.
//   in each prefix directory, like /var/data/otrng-prekey-storage/1234, there can be a .lock file as well. This is only there
//   when the directory is about to be added to, or when the directory will be removed
//   same as the top level directory, if /var/data/otrng-prekey-storage/1234 will be removed, we will create a .lock file, and remove the directory and then remove the .lock file
//   - same thing when we create the directory.
//   - The cleanup method is in charge of deleting empty directories - we don't care about that in the main path

type fileStorageFactory struct {
	desc string
}

func (fsf *fileStorageFactory) createStorage() storage {
	return createFileStorageFrom(fsf.desc)
}

type fileStorage struct {
	path string
}

func isFileStorageDescriptor(desc string) bool {
	return strings.HasPrefix(desc, "dir:")
}

func createFileStorageFrom(descriptor string) *fileStorage {
	path := strings.TrimPrefix(descriptor, "dir:")
	return &fileStorage{
		path: path,
	}
}

func (fs *fileStorage) storeClientProfile(from string, cp *clientProfile) error {
	// TODO: implement
	return nil
}

func (fs *fileStorage) storePrekeyProfile(string, *prekeyProfile) error {
	// TODO: implement
	return nil
}

func (fs *fileStorage) storePrekeyMessages(string, []*prekeyMessage) error {
	// TODO: implement
	return nil
}

func (fs *fileStorage) numberStored(string, uint32) uint32 {
	// TODO: implement
	return 0
}

func (fs *fileStorage) retrieveFor(string) []*prekeyEnsemble {
	// TODO: implement
	return nil
}

func (fs *fileStorage) cleanup() {
	// TODO: implement
}
