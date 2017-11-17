var cpuChart = echarts.init(document.getElementById('cpu'));
var memoryChart = echarts.init(document.getElementById('memory'));
var flowChart = echarts.init(document.getElementById('flow'));

$.ajax({
  type: "get",
  url: location.href,
  data: {
    type: 'api'
  }
}).done(function(res){
  var deviceData = JSON.parse(res.data);
  var memory = deviceData.memory,
      cpu = deviceData.CPU,
      flow = deviceData.flow;
  // console.log(memory, cpu, flow);
  var cpuOption = {
    title: {
      text: 'CPU 使用率',
      x: 'center'
    },
    tooltip: {
      trigger: 'item',
      formatter: '{b} {d}%'
    },
    legend: {
      orient: 'vertical',
      left: 'left',
      data: ['已使用', '未使用']
    },
    series: [
      {
        name: 'CPU 使用率',
        type: 'pie',
        radius: '55%',
        center: ['50%', '60%'],
        data: [
          { value: cpu, 
            name: '已使用',
            label: {
              normal: {
                show: true,
                formatter: '{b} {d}%'
              }
            }
          }, 
          { value: 100 - cpu, 
            name: '未使用',
            label: {
              normal: {
                show: true,
                formatter: '{b} {d}%'
              }
            }
          }
        ],
        itemStyle: {
          emphasis: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0, 0, 0, 0.5)'
          }
        }
      }
    ]
  };
  
  var memoryOption = {
    title: {
      text: '内存使用率',
      x: 'center'
    },
    tooltip: {
      trigger: 'item',
      formatter: '{b} {d}%'
    },
    legend: {
      orient: 'vertical',
      left: 'left',
      data: ['已使用', '未使用']
    },
    series: [
      {
        name: '内存使用率',
        type: 'pie',
        radius: '55%',
        center: ['50%', '60%'],
        data: [
          { 
            value: memory, 
            name: '已使用',
            label: {
              normal: {
                show: true,
                formatter: '{b} {d}%'
              }
            }
          }, { 
            value: 8000 - memory, 
            name: '未使用',
            label: {
              normal: {
                show: true,
                formatter: '{b} {d}%'
              }
            } 
          }
        ],
        itemStyle: {
          emphasis: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0, 0, 0, 0.5)'
          }
        }
      }
    ]
  };
  
  var flowOption = {
    title: {
      text: '网络流量'
    },
    tooltip: {
      trigger: 'axis'
    },
    legend: {
      data:['网络流量']
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      name: '时间(h)',
      boundaryGap: false,
      data: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23']
    },
    yAxis: {
      type: 'value',
      name: '流量(MB)'
    },
    series: [
      {
        name: '网络流量',
        type: 'line',
        stack: '总量',
        data: flow
      }
    ]
  };
  
  cpuChart.setOption(cpuOption);
  memoryChart.setOption(memoryOption);
  flowChart.setOption(flowOption);
});
