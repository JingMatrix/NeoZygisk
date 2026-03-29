#include "files.hpp"

#include <cstdlib>
#include <sys/sysmacros.h>

using namespace std::string_view_literals;

void file_readline(bool trim, FILE *fp, const std::function<bool(std::string_view)> &fn) {
    size_t len = 1024;
    char *buf = (char *) malloc(len);
    char *start;
    ssize_t read;
    while ((read = getline(&buf, &len, fp)) >= 0) {
        start = buf;
        if (trim) {
            while (read && "\n\r "sv.find(buf[read - 1]) != std::string::npos) --read;
            buf[read] = '\0';
            while (*start == ' ') ++start;
        }
        if (!fn(start)) break;
    }
    free(buf);
}

void file_readline(bool trim, const char *file, const std::function<bool(std::string_view)> &fn) {
    if (auto fp = open_file(file, "re")) file_readline(trim, fp.get(), fn);
}
void file_readline(const char *file, const std::function<bool(std::string_view)> &fn) {
    file_readline(false, file, fn);
}

sDIR make_dir(DIR *dp) {
    return sDIR(dp, [](DIR *dp) { return dp ? closedir(dp) : 1; });
}

sFILE make_file(FILE *fp) {
    return sFILE(fp, [](FILE *fp) { return fp ? fclose(fp) : 1; });
}
