// bubblesort_simple.cpp
// Simple Bubble Sort - sorts an array in ascending order

#include <iostream>

void bubbleSort(int arr[], int n) {
    for (int i = 0; i < n - 1; ++i) {
        for (int j = 0; j < n - 1 - i; ++j) {
            if (arr[j] > arr[j+1]) {
                std::swap(arr[j], arr[j+1]);
            }
        }
    }
}

int main() {
    int arr[] = {64, 34, 25, 12, 22, 11, 90};
    int n = sizeof(arr) / sizeof(arr[0]);

    std::cout << "Before: ";
    for (int x : arr) std::cout << x << " ";
    std::cout << "\n";

    bubbleSort(arr, n);

    std::cout << "After : ";
    for (int x : arr) std::cout << x << " ";
    std::cout << "\n";
    return 0;
}
