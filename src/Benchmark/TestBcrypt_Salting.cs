using System.Collections.Generic;
using Benchmark._3._2._1;
using Benchmark._3._5.perfmerge_1;
using Benchmark._4._0._0;
using BenchmarkDotNet.Attributes;
#pragma warning disable 1591

namespace BCrypt.Net.Benchmarks
{
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    [KeepBenchmarkFiles]
    public class TestBcrypt_Salting
    {
        [Benchmark(Baseline = true)]
        public string TestSaltGenerate()
        {
            return version4.BCrypt.GenerateSalt();
        }

        [Benchmark]
        public string TestSaltGenerateCurrent()
        {
            return BCrypt.GenerateSalt();
        }
    }
}
