#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

void bubbleSort(vector<int>& arr) {
    int n = arr.size();
    bool swapped;

    for (int i = 0; i < n - 1; i++) {
        swapped = false;
        
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                swap(arr[j], arr[j + 1]);
                swapped = true;
            }
        }

        if (swapped == false)
            break;
    }
}

void printArray(const vector<int>& arr) {
    for (int element : arr) {
        cout << element << " ";
    }
    cout << "\n";
}

int main() {
    vector<int> data = {64, 34, 25, 12, 22, 11, 90};

    cout << "Original array: ";
    printArray(data);

    bubbleSort(data);

    cout << "Sorted array: ";
    printArray(data);

    return 0;
}