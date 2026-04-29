import pyshark
import pyshark.tshark.tshark
import numpy as np
import pandas as pd
import time


path = r'D:\Wireshark\tshark.exe'
interface_name = r'\Device\NPF_{73ABBB68-479C-43DF-96F1-D2031FEEA17A}'


class SinglePacketExtractor:
    """Извлекает признаки из одного пакета"""

    def extract(self, packet):
        features = {}

        features['Tot size'] = float(packet.length)

        if hasattr(packet, 'ip'):
            try:
                ihl = float(packet.ip.hdr_len)
                features['Header_Length'] = ihl * 4.0 * 8.0
            except (ValueError, AttributeError):
                features['Header_Length'] = 0.0
        else:
            features['Header_Length'] = 0.0

        if hasattr(packet, 'ip'):
            proto = packet.ip.proto
            if proto == '6':
                features['Protocol Type'] = 0.0  # TCP
            elif proto == '17':
                features['Protocol Type'] = 1.0  # UDP
            elif proto == '1':
                features['Protocol Type'] = 2.0  # ICMP
            else:
                try:
                    features['Protocol Type'] = float(proto) + 10.0
                except (ValueError, TypeError):
                    features['Protocol Type'] = 99.0
        else:
            features['Protocol Type'] = -1.0

        if hasattr(packet, 'ip'):
            try:
                features['Duration'] = float(packet.ip.ttl)
            except (ValueError, AttributeError):
                features['Duration'] = 0.0
        else:
            features['Duration'] = 0.0

        features['TCP'] = 1.0 if hasattr(packet, 'tcp') else 0.0
        features['UDP'] = 1.0 if hasattr(packet, 'udp') else 0.0
        features['ICMP'] = 1.0 if hasattr(packet, 'icmp') else 0.0
        features['IPv'] = 1.0 if hasattr(packet, 'ip') else 0.0

        features['fin_flag_number'] = 0.0  # 7
        features['syn_flag_number'] = 0.0  # 8
        features['rst_flag_number'] = 0.0  # 9
        features['psh_flag_number'] = 0.0  # 10
        features['ack_flag_number'] = 0.0  # 11
        features['ece_flag_number'] = 0.0  # 12
        features['cwr_flag_number'] = 0.0  # 13

        features['urg_count'] = 0.0

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
            try:
                flags = int(packet.tcp.flags, 16)
                features['fin_flag_number'] = 1.0 if (flags & 0x001) else 0.0
                features['syn_flag_number'] = 1.0 if (flags & 0x002) else 0.0
                features['rst_flag_number'] = 1.0 if (flags & 0x004) else 0.0
                features['psh_flag_number'] = 1.0 if (flags & 0x008) else 0.0
                features['ack_flag_number'] = 1.0 if (flags & 0x010) else 0.0
                features['urg_count'] = 1.0 if (flags & 0x020) else 0.0
                features['ece_flag_number'] = 1.0 if (flags & 0x040) else 0.0
                features['cwr_flag_number'] = 1.0 if (flags & 0x080) else 0.0
            except (ValueError, AttributeError):
                pass

        src_port = 0
        dst_port = 0

        try:
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
        except (ValueError, AttributeError):
            pass

        features['HTTP'] = 1.0 if dst_port in [80, 8080, 8000] else 0.0  # 19
        features['HTTPS'] = 1.0 if dst_port == 443 else 0.0  # 20
        features['DNS'] = 1.0 if dst_port == 53 else 0.0  # 21
        features['Telnet'] = 1.0 if dst_port == 23 else 0.0  # 22
        features['SMTP'] = 1.0 if dst_port in [25, 587] else 0.0  # 23
        features['SSH'] = 1.0 if dst_port == 22 else 0.0  # 24
        features['IRC'] = 1.0 if dst_port in [6667, 6668, 6669] else 0.0  # 25

        if hasattr(packet, 'udp'):
            try:
                src_port_udp = int(packet.udp.srcport)
                dst_port_udp = int(packet.udp.dstport)
                features['DHCP'] = 1.0 if src_port_udp in [67, 68] or dst_port_udp in [67, 68] else 0.0
            except (ValueError, AttributeError):
                features['DHCP'] = 0.0
        else:
            features['DHCP'] = 0.0

        features['ARP'] = 1.0 if hasattr(packet, 'arp') else 0.0
        features['LLC'] = 1.0 if hasattr(packet, 'llc') else 0.0

        if hasattr(packet, 'ip'):
            features['_src_ip'] = packet.ip.src
            features['_dst_ip'] = packet.ip.dst
            features['_src_port'] = float(src_port)
            features['_dst_port'] = float(dst_port)
        elif hasattr(packet, 'arp'):
            features['_src_ip'] = getattr(packet.arp, 'src.proto_ipv4', '0.0.0.0')
            features['_dst_ip'] = getattr(packet.arp, 'dst.proto_ipv4', '0.0.0.0')
            features['_src_port'] = 0.0
            features['_dst_port'] = 0.0
        else:
            features['_src_ip'] = '0.0.0.0'
            features['_dst_ip'] = '0.0.0.0'
            features['_src_port'] = 0.0
            features['_dst_port'] = 0.0

        return features


class FlowStatistics:
    """Считает статистические признаки для flow с ТОЧНЫМИ названиями"""

    def __init__(self):
        self.packets = []
        self.start_time = None

        self._ack_count = 0.0  # 14
        self._syn_count = 0.0  # 15
        self._fin_count = 0.0  # 16
        self._rst_count = 0.0  # 18

        self._packet_sizes = []
        self._timestamps = []

    def add_packet(self, packet_features):
        """Добавляет пакет в flow"""
        self.packets.append(packet_features)

        if self.start_time is None:
            self.start_time = packet_features.get('_timestamp', time.time())

        self._ack_count += float(packet_features.get('ack_flag_number', 0.0))
        self._syn_count += float(packet_features.get('syn_flag_number', 0.0))
        self._fin_count += float(packet_features.get('fin_flag_number', 0.0))
        self._rst_count += float(packet_features.get('rst_flag_number', 0.0))

        self._packet_sizes.append(float(packet_features.get('Tot size', 0.0)))
        self._timestamps.append(float(packet_features.get('_timestamp', time.time())))

    def get_statistical_features(self):
        """Возвращает статистические признаки flow"""
        if len(self.packets) < 2:
            return None

        stats = {}

        end_time = float(self._timestamps[-1])
        stats['flow_duration'] = end_time - float(self.start_time)

        if stats['flow_duration'] > 0:
            stats['Rate'] = float(len(self.packets)) / stats['flow_duration']
        else:
            stats['Rate'] = 0.0

        stats['Srate'] = float(stats['Rate'])
        stats['Drate'] = float(stats['Rate'])

        stats['ack_count'] = float(self._ack_count)
        stats['syn_count'] = float(self._syn_count)
        stats['fin_count'] = float(self._fin_count)
        stats['rst_count'] = float(self._rst_count)

        stats['Tot sum'] = float(np.sum(self._packet_sizes))

        stats['Min'] = float(np.min(self._packet_sizes)) if self._packet_sizes else 0.0
        stats['Max'] = float(np.max(self._packet_sizes)) if self._packet_sizes else 0.0
        stats['AVG'] = float(np.mean(self._packet_sizes)) if self._packet_sizes else 0.0

        if len(self._packet_sizes) > 1:
            stats['Std'] = float(np.std(self._packet_sizes, ddof=1))
        else:
            stats['Std'] = 0.0

        stats['Number'] = float(len(self.packets))

        if len(self._timestamps) > 1:
            try:
                iats = np.diff(np.array(self._timestamps, dtype=float))
                if len(iats) > 0:
                    stats['IAT'] = float(np.mean(iats))
                else:
                    stats['IAT'] = 0.0
            except Exception:
                stats['IAT'] = 0.0
        else:
            stats['IAT'] = 0.0

        try:
            stats['Magnitue'] = float(np.sqrt(stats['Tot sum'] ** 2 + stats['Number'] ** 2))
        except Exception:
            stats['Magnitue'] = 0.0

        try:
            stats['Radius'] = float(np.sqrt(stats['AVG'] ** 2 + stats['Std'] ** 2))
        except Exception:
            stats['Radius'] = 0.0

        if len(self._packet_sizes) > 1:
            stats['Variance'] = float(np.var(self._packet_sizes, ddof=1))
        else:
            stats['Variance'] = 0.0

        try:
            stats['Weight'] = float(stats['Tot sum'] / 1000.0)
        except Exception:
            stats['Weight'] = 0.0

        if len(self._packet_sizes) > 1 and len(self._timestamps) > 1:
            try:
                sizes_for_cov = self._packet_sizes[:-1]
                iats_for_cov = np.diff(np.array(self._timestamps, dtype=float))

                min_len = min(len(sizes_for_cov), len(iats_for_cov))
                if min_len > 1:
                    sizes_for_cov = sizes_for_cov[:min_len]
                    iats_for_cov = iats_for_cov[:min_len]

                    cov_matrix = np.cov(sizes_for_cov, iats_for_cov)
                    if cov_matrix.shape == (2, 2):
                        stats['Covariance'] = float(cov_matrix[0, 1])
                    else:
                        stats['Covariance'] = 0.0
                else:
                    stats['Covariance'] = 0.0
            except Exception as e:
                stats['Covariance'] = 0.0
        else:
            stats['Covariance'] = 0.0

        return stats


class NetworkFeatureExtractor:
    """Главный класс - объединяет всё"""

    def __init__(self):
        self.packet_extractor = SinglePacketExtractor()
        self.flows = {}  # flow_key -> FlowStatistics

    def _get_flow_key(self, packet_features):
        """Создаёт уникальный ключ для flow"""
        return (
            packet_features.get('_src_ip', '0.0.0.0'),
            packet_features.get('_dst_ip', '0.0.0.0'),
            float(packet_features.get('_src_port', 0.0)),
            float(packet_features.get('_dst_port', 0.0)),
            float(packet_features.get('Protocol Type', -1.0))
        )

    def process_packet(self, packet):
        """Обрабатывает один pyshark пакет"""
        packet_features = self.packet_extractor.extract(packet)
        packet_features['_timestamp'] = float(time.time())  # временная метка как float
        flow_key = self._get_flow_key(packet_features)

        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStatistics()

        self.flows[flow_key].add_packet(packet_features)

        if len(self.flows[flow_key].packets) >= 10:
            flow_stats = self.flows[flow_key].get_statistical_features()

            if flow_stats:
                all_features = {}

                for key in packet_features:
                    if not key.startswith('_'):
                        all_features[key] = float(packet_features[key])

                all_features.update(flow_stats)

                return all_features

        return None

    def get_all_features_list(self):
        """Возвращает список всех 46 признаков в правильном порядке"""
        return [
            'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',
            'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
            'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
            'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count',
            'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS',
            'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
            'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std',
            'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance',
            'Variance', 'Weight'
        ]

    def get_features_as_ordered_array(self, features_dict):
        """Преобразует словарь признаков в упорядоченный массив float"""
        ordered_features = []
        for feature_name in self.get_all_features_list():
            if feature_name in features_dict:
                ordered_features.append(float(features_dict[feature_name]))
            else:
                ordered_features.append(0.0)
        return np.array(ordered_features, dtype=float)

def test_extractor():
    """Тестируем извлечение признаков"""

    path = r'D:\Wireshark\tshark.exe'
    interface = r'\Device\NPF_{73ABBB68-479C-43DF-96F1-D2031FEEA17A}'

    print(" Тестируем извлечение признаков...")

    # Создаём экстрактор
    extractor = NetworkFeatureExtractor()

    try:
        capture = pyshark.LiveCapture(
            interface=interface,
            tshark_path=path,
            display_filter='ip'
        )

        all_extracted_features = []

        for i, packet in enumerate(capture.sniff_continuously()):
            if i >= 30:
                break

            features = extractor.process_packet(packet)

            if features:
                print(f"\n Извлёк признаки из flow (пакетов: {i + 1})")

                df = pd.DataFrame([features])

                # Проверяем колонки
                expected_columns = extractor.get_all_features_list()
                missing = set(expected_columns) - set(df.columns)

                if missing:
                    print(f"❌ Отсутствуют колонки: {missing}")
                    for col in missing:
                        df[col] = 0

                # Упорядочиваем
                df = df[expected_columns]

                print(f"DataFrame: {df.shape}")
                print(f"   Признаков: {len(df.columns)}")

                all_extracted_features.append(df)

                print("\nПервые 10 признаков:")
                for col in df.columns[:10]:
                    print(f"   {col}: {df[col].values[0]}")

        if all_extracted_features:
            result_df = pd.concat(all_extracted_features, ignore_index=True)
            result_df.to_csv('extracted_features.csv', index=False)
            print(f"\n Сохранено {len(result_df)} наборов признаков в extracted_features.csv")

            train_df = pd.read_csv('../data_eda/final_data.csv')
            train_columns = [col for col in train_df.columns if col not in ['category', 'label']]

            print(f"\n📊 Сравнение с обучающими данными:")
            print(f"   Обучающие колонки: {len(train_columns)}")
            print(f"   Наши колонки: {len(result_df.columns)}")
            print(f"   Совпадают: {set(train_columns) == set(result_df.columns)}")

        else:
            print("❌ Не удалось извлечь признаки flow")

    except Exception as e:
        print(f"❌ Ошибка: {e}")


if __name__ == "__main__":
    test_extractor()