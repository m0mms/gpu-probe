extern "C" __global__ void base(const double *input, double *output, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) output[i] = 2.0 * input[i] + 1.0;
}
