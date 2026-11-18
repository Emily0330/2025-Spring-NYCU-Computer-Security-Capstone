#include<stdlib.h>
#include<stdio.h>
#include<time.h>

unsigned int long_secure_random() {
	srand(time(NULL));
	unsigned int r[100];
	for (int i = 0; i < 100; i ++) {
		r[i] = rand() % 32323;
	}
	for (int i = 1; i < 100; i ++) {
		r[i] = r[i] * r[i - 1] * r[i - 1] * r[i - 1] + r[i] * r[i - 1] * r[i - 1] * 3 + r[i] * r[i - 1] * 2 + r[i];
	}
	return r[99];
}

int main() {

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	unsigned int val = long_secure_random();

	printf("%u", val);

	return 0;
}
